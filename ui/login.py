"""Login 2 langkah: (1) password PBKDF2  (2) verifikasi wajah bila biometrik sudah didaftarkan."""
import base64
import os

import streamlit as st

from modules import biometric
from modules.auth import verify_password
from modules.database import execute_query

MAX_FACE_ATTEMPTS = 3


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


def _password_step(blockchain, on_success):
    if st.session_state.get("login_error"):
        st.error(st.session_state.pop("login_error"))
    with st.form("login_form", clear_on_submit=False):
        st.text_input("Username / NIM", placeholder="Masukkan NIM atau username", key="login_username")
        st.text_input("Password", type="password", placeholder="Masukkan password", key="login_password")
        submit = st.form_submit_button("MASUK KE PORTAL", use_container_width=True)
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
    if biometric.is_enrolled(user["id"]):
        st.session_state.pending_2fa_user = user
        st.session_state.face_attempts = 0
        st.rerun()
    blockchain.add_block({"event": "LOGIN", "user": user["username"], "method": "password"})
    on_success(user, biometric_ok=False)


def _face_step(user, blockchain, on_success):
    st.markdown(f"#### 🧬 Langkah 2 — Verifikasi Wajah\nHalo **{user['username']}**, password benar. "
                f"Hadapkan wajah ke kamera lalu ambil foto.")
    attempts = st.session_state.get("face_attempts", 0)
    shot = st.camera_input("Verifikasi wajah", key=f"login_cam_{attempts}", label_visibility="collapsed")
    if shot is not None:
        ok, score, thr, msg = biometric.verify(user["id"], shot.getvalue())
        if ok:
            st.session_state.pop("pending_2fa_user", None)
            blockchain.add_block({"event": "LOGIN", "user": user["username"], "method": "password+face",
                                  "face_score": round(score, 3)})
            on_success(user, biometric_ok=True)
            return
        attempts += 1
        st.session_state.face_attempts = attempts
        if attempts >= MAX_FACE_ATTEMPTS:
            st.session_state.pop("pending_2fa_user", None)
            blockchain.add_block({"event": "LOGIN_FAILED_BIOMETRIC", "user": user["username"], "attempts": attempts})
            st.session_state.login_error = "❌ Verifikasi wajah gagal 3 kali. Silakan login ulang."
        else:
            st.session_state.login_error = f"{msg} Sisa percobaan: {MAX_FACE_ATTEMPTS - attempts}."
        st.rerun()
    if st.session_state.get("login_error"):
        st.error(st.session_state.pop("login_error"))
    if st.button("⬅️ Batal / ganti akun"):
        st.session_state.pop("pending_2fa_user", None)
        st.rerun()
