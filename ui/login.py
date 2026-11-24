"""Login 2 langkah: (1) password PBKDF2  (2) verifikasi wajah bila biometrik sudah didaftarkan."""
import base64
import os

import streamlit as st

from modules import biometric, session
from modules.auth import verify_password
from modules.database import execute_query


def _hero():
    logo = ""
    if os.path.exists("assets/logo_upnvy.png"):
        with open("assets/logo_upnvy.png", "rb") as f:
            logo = base64.b64encode(f.read()).decode()
    st.markdown(f"""
    <div class="login-hero">
        <div class="login-container">
            <div class="login-logo">
                <img src="data:image/png;base64,{logo}" width="100" onerror="this.style.display='none'">
            </div>
            <h1>SRIKANDI</h1>
            <p class="subtitle">Sistem Ujian Daring<br>Universitas Pembangunan Nasional "Veteran" Yogyakarta</p>
        </div>
    </div>
    """, unsafe_allow_html=True)


def render(blockchain, on_success):
    st.markdown("""
    <style>
        [data-testid="stSidebar"] { display: none; }
        .block-container { max-width: 100% !important; padding: 0 !important; }
    </style>
    """, unsafe_allow_html=True)
    _hero()
    _, col, _ = st.columns([1, 2, 1])
    with col:
        pending = st.session_state.get("pending_2fa_user")
        with st.container(border=True):
            if pending:
                _face_step(pending, blockchain, on_success)
            else:
                _password_step(blockchain, on_success)
        st.markdown("""
        <div class="login-footer">
            <p>🔒 Dongle Ed25519 · Login PBKDF2-SHA256 + Face ID · Soal super-enkripsi Vigenère + AES-256-GCM ·
            File ChaCha20-Poly1305 · Token Steganografi · Blockchain Audit</p>
        </div>
        """, unsafe_allow_html=True)


def start_face_step(user, blockchain):
    """Pindah ke langkah 2. False (dengan pesan error) jika akun sedang terkunci."""
    wait = session.face_lock_remaining(user["id"])
    if wait:
        st.session_state.login_error = (f"🔒 Verifikasi wajah akun **{user['username']}** dikunci karena gagal "
                                        f"{session.FACE_MAX_ATTEMPTS} kali. Coba lagi dalam {session.fmt_wait(wait)}.")
        return False
    st.session_state.pending_2fa_user = session.public_user(user)
    return True


def _password_step(blockchain, on_success):
    if st.session_state.get("login_error"):
        st.error(st.session_state.pop("login_error"))
    with st.form("login_form", clear_on_submit=False):
        st.text_input("Username / NIM", placeholder="Masukkan NIM atau username", key="login_username")
        st.text_input("Password", type="password", placeholder="Masukkan password", key="login_password")
        submit = st.form_submit_button("MASUK KE PORTAL", width="stretch")
    if not submit:
        return
    username = st.session_state.login_username.strip()
    password = st.session_state.login_password.strip()
    if not username or not password:
        st.error("Username dan password wajib diisi!")
        return
    user = execute_query("SELECT * FROM users WHERE username = %s", (username,))
    if not (user and verify_password(user["password_hash"], password)):
        st.error("Username atau password salah!")
        return

    state, _, detail = biometric.status(user["id"])
    if state == "active":
        start_face_step(user, blockchain)
        st.rerun()
    if state == "corrupt":
        # Template tidak bisa dibuka: setara dengan belum terdaftar (menghapus template lewat database
        # juga berefek sama), tetapi dicatat di blockchain & ditandai di menu Integritas Aset.
        blockchain.add_block({"event": "BIOMETRIC_TEMPLATE_UNREADABLE", "user": user["username"], "detail": detail})
    blockchain.add_block({"event": "LOGIN", "user": user["username"], "method": "password"})
    on_success(user, session.AMR_PASSWORD)


def _face_step(pending, blockchain, on_success):
    user_id = pending["id"]
    st.markdown(f"#### 🧬 Langkah 2 — Verifikasi Wajah\nHalo **{pending['username']}**, password benar. "
                f"Hadapkan wajah ke kamera lalu ambil foto.")
    st.caption("Kamera hanya bisa dipakai jika aplikasi dibuka lewat http://localhost atau HTTPS, "
               "dan izin kamera di browser diberikan.")

    wait = session.face_lock_remaining(user_id)
    if wait:
        st.session_state.pop("pending_2fa_user", None)
        st.session_state.login_error = f"🔒 Verifikasi wajah dikunci. Coba lagi dalam {session.fmt_wait(wait)}."
        st.rerun()

    attempts = session.face_attempts(user_id)
    retry = st.session_state.get("face_retry", 0)
    shot = st.camera_input("Verifikasi wajah", key=f"login_cam_{user_id}_{attempts}_{retry}",
                           label_visibility="collapsed")
    if shot is not None:
        ok, score, thr, msg, reason = biometric.verify(user_id, shot.getvalue(), with_reason=True)
        if ok:
            user = execute_query("SELECT * FROM users WHERE id = %s", (user_id,))
            if not user:
                st.session_state.pop("pending_2fa_user", None)
                st.session_state.login_error = "Akun tidak ditemukan. Silakan login ulang."
                st.rerun()
            session.reset_face_failures(user_id)
            st.session_state.pop("pending_2fa_user", None)
            blockchain.add_block({"event": "LOGIN", "user": user["username"], "method": "password+face",
                                  "face_score": round(score, 3)})
            on_success(user, session.AMR_FACE)
            return
        if reason in ("no_face", "bad_image"):
            # Foto tanpa wajah bukan percobaan pencocokan -> tidak mengurangi jatah; kamera direset.
            st.session_state.face_retry = retry + 1
            st.session_state.login_error = f"{msg} (tidak dihitung sebagai percobaan gagal)"
        elif reason in ("corrupt", "no_data"):
            st.session_state.pop("pending_2fa_user", None)
            st.session_state.login_error = f"{msg} Silakan login ulang."
        else:
            attempts, locked = session.register_face_failure(user_id)
            if locked:
                st.session_state.pop("pending_2fa_user", None)
                blockchain.add_block({"event": "LOGIN_FAILED_BIOMETRIC", "user": pending["username"],
                                      "attempts": attempts, "locked_minutes": session.FACE_LOCK_MINUTES})
                st.session_state.login_error = (f"❌ Verifikasi wajah gagal {attempts} kali. Akun dikunci "
                                                f"{session.FACE_LOCK_MINUTES} menit.")
            else:
                st.session_state.login_error = (f"{msg} Sisa percobaan: "
                                                f"{session.FACE_MAX_ATTEMPTS - attempts}.")
        st.rerun()
    if st.session_state.get("login_error"):
        st.error(st.session_state.pop("login_error"))
    if st.button("⬅️ Batal / ganti akun"):
        st.session_state.pop("pending_2fa_user", None)
        st.rerun()
