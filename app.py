import base64
import hashlib
import hmac
import os
import secrets
import time

import streamlit as st
import streamlit.components.v1 as components

st.set_page_config(
    page_title="SRIKANDI - Secure Exam System",
    page_icon="🎓",
    layout="wide",
    initial_sidebar_state="expanded",
)

from modules.auth import check_dongle
from modules.blockchain import SimpleBlockchain
from modules.database import ensure_schema, execute_query
from modules.migrations import run_migrations
from modules import biometric
from modules.messages import unread_count
from modules.token_policy import window_state
from ui import blockchain_page, kelola, login, messages_page, profile, student
from ui.common import render_header

# Paksa tampilkan kembali header dan tombol toggle sidebar Streamlit
components.html("""
<script>
    const targetDoc = window.parent.document;
    const header = targetDoc.querySelector('[data-testid="stHeader"]');
    if (header) { header.style.display = 'flex'; header.style.visibility = 'visible'; }
    const collapseBtn = targetDoc.querySelector('[data-testid="collapsedControl"]');
    if (collapseBtn) { collapseBtn.style.display = 'block'; collapseBtn.style.visibility = 'visible'; }
</script>
""", height=0)

if os.path.exists("utils/style.css"):
    with open("utils/style.css", encoding="utf-8") as f:
        st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)

# ==================== 1. DONGLE: aplikasi hanya hidup jika flashdisk dongle asli terpasang ====================
dongle_ok, dongle_msg = check_dongle()
if not dongle_ok:
    st.error(f"🔒 **APLIKASI TERKUNCI**: {dongle_msg}")
    st.info("Cara membuat dongle: colokkan flashdisk, lalu jalankan `python buat_dongle.py` di folder proyek.")
    st.stop()

ensure_schema()
blockchain = SimpleBlockchain()
if "migrations_done" not in st.session_state:
    run_migrations(blockchain)  # enkripsi data lama yang masih plaintext + baseline blockchain
    st.session_state.migrations_done = True

# ==================== SESI (token bertanda tangan HMAC-SHA256) ====================
SESSION_PARAM = "exam_session"
MENU_PARAM = "exam_page"
SECRET_PATH = os.path.join("config", "session.key")
os.makedirs("config", exist_ok=True)
if not os.path.exists(SECRET_PATH):
    with open(SECRET_PATH, "wb") as secret_file:
        secret_file.write(secrets.token_bytes(32))
with open(SECRET_PATH, "rb") as secret_file:
    SESSION_SECRET = secret_file.read()


def signed_session(username):
    expires = int(time.time()) + 60 * 60 * 24 * 7
    payload = f"{username}|{expires}"
    signature = hmac.new(SESSION_SECRET, payload.encode(), hashlib.sha256).hexdigest()
    return base64.urlsafe_b64encode(f"{payload}|{signature}".encode()).decode()


def restore_session():
    try:
        token = st.query_params.get(SESSION_PARAM)
        if not token:
            return None
        payload = base64.urlsafe_b64decode(token.encode()).decode()
        username, expires, signature = payload.rsplit("|", 2)
        expected = hmac.new(SESSION_SECRET, f"{username}|{expires}".encode(), hashlib.sha256).hexdigest()
        if int(expires) < int(time.time()) or not hmac.compare_digest(signature, expected):
            return None
        return execute_query("SELECT * FROM users WHERE username = %s", (username,))
    except (ValueError, TypeError, UnicodeDecodeError):
        return None


if "logged_in" not in st.session_state:
    restored_user = restore_session()
    st.session_state.logged_in = restored_user is not None
    st.session_state.user = restored_user
    st.session_state.active_exam = None
    st.session_state.current_question_idx = 0
    st.session_state.student_answers = {}
    st.session_state.editing_exam_id = None
    st.session_state.token_target_exam_id = None


def on_login_success(user, biometric_ok):
    st.session_state.logged_in = True
    st.session_state.user = user
    st.query_params[SESSION_PARAM] = signed_session(user["username"])
    st.rerun()


# ==================== LOGIN PAGE ====================
if not st.session_state.logged_in:
    login.render(blockchain, on_login_success)
    st.stop()

current_user = st.session_state.user
role = current_user["role"]

# ==================== SIDEBAR ====================
with st.sidebar:
    st.markdown("""
    <div class="sidebar-brand">
        <div class="brand-icon">🎓</div>
        <div class="brand-text">
            <h3>SRIKANDI</h3>
            <p>Secure Exam System</p>
        </div>
    </div>
    """, unsafe_allow_html=True)
    st.markdown(f"""
    <div class="user-card">
        <div class="user-avatar">👤</div>
        <div class="user-info">
            <p class="user-name">{current_user['username']}</p>
            <p class="user-role">{role.upper()}</p>
        </div>
    </div>
    """, unsafe_allow_html=True)
    st.markdown("<div class='menu-label'>MENU UTAMA</div>", unsafe_allow_html=True)

    unread = unread_count(current_user)
    msg_label = f"💬 Pesan ({unread})" if unread else "💬 Pesan"
    work_label = "📝 Kelola Ujian" if role == "proctor" else "📝 Ujian Saya"
    menu_values = {
        "dashboard": "🏠 Dashboard",
        "work": work_label,
        "messages": msg_label,
        "blockchain": "⛓️ Blockchain Log",
        "profile": "👤 Profil",
        "logout": "🚪 Keluar",
    }
    menu_items = list(menu_values.values())
    saved_page = st.query_params.get(MENU_PARAM, "dashboard")
    default_menu = menu_values.get(saved_page, menu_items[0])
    menu = st.radio("Menu Utama", menu_items, index=menu_items.index(default_menu), key=f"main_menu_{unread}",
                    label_visibility="collapsed")
    page = next(key for key, value in menu_values.items() if value == menu)
    st.query_params[MENU_PARAM] = page
    st.caption(f"🔑 {dongle_msg}")

    if page == "logout":
        blockchain.add_block({"event": "LOGOUT", "user": current_user["username"]})
        for key in list(st.session_state.keys()):
            if key != "migrations_done":
                del st.session_state[key]
        st.query_params.clear()
        st.rerun()


# ==================== DASHBOARD ====================
def security_checklist():
    """Status penerapan 7 ketentuan proyek (dihitung langsung dari sistem)."""
    chain_ok, _ = blockchain.validate_chain()
    enrolled = execute_query("SELECT COUNT(*) AS n FROM users WHERE biometric_template IS NOT NULL")["n"]
    n_q = execute_query("SELECT COUNT(*) AS n FROM exam_questions")["n"]
    n_files = execute_query("SELECT COUNT(*) AS n FROM exam_files WHERE encrypted_file IS NOT NULL")["n"]
    n_stego = execute_query("SELECT COUNT(*) AS n FROM exam_stego_tokens")["n"]
    n_blocks = execute_query("SELECT COUNT(*) AS n FROM blockchain_logs")["n"]
    plain_tokens = execute_query(
        "SELECT COUNT(*) AS n FROM exams WHERE token_hash <> 'PDF_MODE' AND token_hash NOT LIKE 'pbkdf2_sha256$%%'")["n"]
    rows = [
        ("Login biometrik & hanya hidup dengan dongle", True,
         f"Dongle Ed25519 aktif · {enrolled} pengguna terdaftar Face ID (LBPH)"),
        ("Login memakai algoritma kriptografi", True, "PBKDF2-HMAC-SHA256 + salt · sesi HMAC-SHA256"),
        ("Pesan teks super-enkripsi (klasik + modern)", True,
         f"Extended Vigenère + AES-256-GCM · {n_q} soal, kunci jawaban, jawaban, token, pesan"),
        ("File dienkripsi dengan algoritma berbeda", True, f"ChaCha20-Poly1305 + PBKDF2 · {n_files} file PDF"),
        ("Pesan penting terenkripsi di basis data", plain_tokens == 0,
         "Semua token/kunci/jawaban/template terenkripsi" if plain_tokens == 0 else f"{plain_tokens} token masih plaintext"),
        ("Pesan gambar diamankan steganografi", True, f"LSB + payload terenkripsi · {n_stego} gambar token"),
        ("Aset penting diamankan blockchain", chain_ok, f"{n_blocks} blok · rantai {'valid' if chain_ok else 'RUSAK'}"),
    ]
    with st.container(border=True):
        st.markdown("#### 🛡️ Status Ketentuan Keamanan Proyek")
        for name, ok, detail in rows:
            st.markdown(f"{'✅' if ok else '⚠️'} **{name}** — {detail}")


if page == "dashboard":
    render_header(f"Selamat Datang, {current_user['username']}!", "Sistem keamanan ujian aktif · Dongle terverifikasi")
    if not biometric.is_enrolled(current_user["id"]):
        st.warning("🧬 Biometrik wajah Anda belum didaftarkan. Buka menu **👤 Profil** untuk mengaktifkan login Face ID.")
    if role == "student":
        exams = execute_query("SELECT * FROM exams ORDER BY id DESC", fetch=True) or []
        subs = execute_query("SELECT * FROM student_submissions WHERE user_id = %s", (current_user["id"],), fetch=True) or []
        avg = sum(float(s["score"]) for s in subs) / len(subs) if subs else 0
        col1, col2, col3 = st.columns(3)
        for col, bg, fg, icon, value, label in [
            (col1, "#e0f2e9", "#1a7f5a", "📚", len(exams), "Ujian Tersedia"),
            (col2, "#e3f2fd", "#1565c0", "✅", len(subs), "Sudah Selesai"),
            (col3, "#fff3e0", "#ef6c00", "🏆", f"{avg:.1f}", "Rata-rata Nilai"),
        ]:
            col.markdown(f"""
            <div class="stat-card">
                <div class="stat-icon" style="background: {bg}; color: {fg};">{icon}</div>
                <div class="stat-info"><h3>{value}</h3><p>{label}</p></div>
            </div>
            """, unsafe_allow_html=True)
        st.markdown("### 📋 Portal Test Seleksi & Daftar Ujian")
        if not exams:
            st.info("Belum ada jadwal ujian yang tersedia.")
        for ex in exams:
            sub = next((s for s in subs if s["exam_id"] == ex["id"]), None)
            state, _ = window_state(ex)
            with st.container(border=True):
                c1, c2 = st.columns([3, 1])
                c1.markdown(f"**{ex['title']}**")
                c1.markdown(f"🔑 **Kode Ujian:** `{ex['exam_code']}` &nbsp;|&nbsp; ⏱️ **Durasi:** {ex['duration_minutes']} Menit"
                            f" &nbsp;|&nbsp; {'🟢 Token berlaku' if state == 'open' else '🟡 Belum berlaku' if state == 'not_yet' else '🔴 Token kedaluwarsa'}")
                if sub:
                    c2.success(f"✅ Sudah Dikerjakan\n\n**Nilai:** {sub['score']}")
                else:
                    c2.warning("⚠️ Belum Dikerjakan")
    else:
        col1, col2, col3, col4 = st.columns(4)
        col1.metric("Total Ujian", len(execute_query("SELECT id FROM exams", fetch=True) or []))
        col2.metric("Mahasiswa", len(execute_query("SELECT id FROM users WHERE role='student'", fetch=True) or []))
        col3.metric("Submit", len(execute_query("SELECT id FROM student_submissions", fetch=True) or []))
        ok, _ = blockchain.validate_chain()
        col4.metric("Blockchain", "✅ Valid" if ok else "⚠️ Error")
    security_checklist()

elif page == "work":
    if role == "proctor":
        kelola.render(current_user, blockchain)
    else:
        student.render(current_user, blockchain)
elif page == "messages":
    messages_page.render(current_user, blockchain)
elif page == "blockchain":
    blockchain_page.render(current_user, blockchain)
elif page == "profile":
    profile.render(current_user, blockchain, dongle_msg)
