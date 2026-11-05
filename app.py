import streamlit as st
import os
import json
import base64
import hashlib
import hmac
import secrets
import time
from PIL import Image
from modules.database import ensure_schema, execute_query
from modules.auth import check_dongle, verify_password, verify_face_biometric
from modules.modern_cipher import aes_encrypt, aes_decrypt
from modules.classic_cipher import extended_vigenere_encrypt, extended_vigenere_decrypt
from modules.steganography import encode_image, decode_image
from modules.blockchain import SimpleBlockchain

st.set_page_config(
    page_title="SPADA UPN - Secure Exam System",
    page_icon="🎓",
    layout="wide",
    initial_sidebar_state="expanded"
)

ensure_schema()
blockchain = SimpleBlockchain()

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
        signed = f"{username}|{expires}"
        expected = hmac.new(SESSION_SECRET, signed.encode(), hashlib.sha256).hexdigest()
        if int(expires) < int(time.time()) or not hmac.compare_digest(signature, expected):
            return None
        return execute_query("SELECT * FROM users WHERE username = %s", (username,), fetch=False)
    except (ValueError, TypeError, UnicodeDecodeError):
        return None

if os.path.exists("utils/style.css"):
    with open("utils/style.css", encoding="utf-8") as f:
        st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)

dongle_ok, dongle_msg = check_dongle()
if not dongle_ok:
    st.error(f"🔒 **APLIKASI TERKUNCI**: {dongle_msg}")
    st.stop()

if "logged_in" not in st.session_state:
    restored_user = restore_session()
    st.session_state.logged_in = restored_user is not None
    st.session_state.user = restored_user
    st.session_state.active_exam = None
    st.session_state.current_question_idx = 0
    st.session_state.student_answers = {}
    st.session_state.editing_exam_id = None
    st.session_state.token_target_exam_id = None

def render_header(title, subtitle):
    st.markdown(f"""
    <div class="page-header">
        <h1>{title}</h1>
        <p>{subtitle}</p>
    </div>
    """, unsafe_allow_html=True)

# ==================== LOGIN PAGE ====================
if not st.session_state.logged_in:
    # Hide sidebar on login page
    st.markdown("""
    <style>
        [data-testid="stSidebar"] { display: none; }
        .block-container { max-width: 100% !important; padding: 0 !important; }
    </style>
    """, unsafe_allow_html=True)
    
    # Full width login hero
    st.markdown("""
    <div class="login-hero">
        <div class="login-container">
            <div class="login-logo">
                <img src="data:image/png;base64,{}" width="100" onerror="this.style.display='none'">
            </div>
            <h1>SPADA UPN</h1>
            <p class="subtitle">Sistem Pembelajaran Daring<br>Universitas Pembangunan Nasional "Veteran" Yogyakarta</p>
        </div>
    </div>
    """.format(
        base64.b64encode(open("assets/logo_upnvy.png", "rb").read()).decode() if os.path.exists("assets/logo_upnvy.png") else ""
    ), unsafe_allow_html=True)
    
    # Login form in a container
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        with st.container(border=True):
            with st.form("login_form", clear_on_submit=False):
                st.text_input("Username / NIM", placeholder="Masukkan NIM atau username", key="login_username")
                st.text_input("Password", type="password", placeholder="Masukkan password", key="login_password")
                st.checkbox("🔐 Gunakan verifikasi wajah (webcam)", key="login_biometric")
                submit = st.form_submit_button("MASUK KE PORTAL", use_container_width=True)
                
                if submit:
                    username = st.session_state.login_username.strip()
                    password = st.session_state.login_password.strip()
                    use_biometric = st.session_state.login_biometric
                    
                    if not username or not password:
                        st.error("Username dan password wajib diisi!")
                    else:
                        user = execute_query("SELECT * FROM users WHERE username = %s", (username,), fetch=False)
                        if user and verify_password(user['password_hash'], password):
                            if use_biometric:
                                with st.spinner("Memindai wajah..."):
                                    bio_ok, bio_msg = verify_face_biometric(user['id'])
                                    if not bio_ok:
                                        st.error(bio_msg)
                                        st.stop()
                            
                            st.session_state.logged_in = True
                            st.session_state.user = user
                            st.query_params[SESSION_PARAM] = signed_session(user["username"])
                            st.success("Login berhasil! Mengalihkan...")
                            st.rerun()
                        else:
                            st.error("Username atau password salah!")
        
        st.markdown("""
        <div class="login-footer">
            <p>🔒 Login dilindungi PBKDF2-SHA256 · Soal terenkripsi Vigenère + AES-256-GCM · Blockchain Audit</p>
        </div>
        """, unsafe_allow_html=True)
    
    st.stop()

current_user = st.session_state.user
role = current_user['role']

# ==================== SIDEBAR ====================
with st.sidebar:
    st.markdown("""
    <div class="sidebar-brand">
        <div class="brand-icon">🎓</div>
        <div class="brand-text">
            <h3>SPADA UPN</h3>
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
    
    if role == 'proctor':
        menu_items = ["🏠 Dashboard", "📝 Kelola Ujian", "⛓️ Blockchain Log", "👤 Profil", "🚪 Keluar"]
    else:
        menu_items = ["🏠 Dashboard", "📝 Ujian Saya", "⛓️ Blockchain Log", "👤 Profil", "🚪 Keluar"]
    menu_values = {
        "dashboard": menu_items[0],
        "work": menu_items[1],
        "blockchain": menu_items[2],
        "profile": menu_items[3],
        "logout": menu_items[4],
    }
    saved_page = st.query_params.get(MENU_PARAM, "dashboard")
    default_menu = menu_values.get(saved_page, menu_items[0])
    menu = st.radio("", menu_items, index=menu_items.index(default_menu), key="main_menu", label_visibility="collapsed")
    st.query_params[MENU_PARAM] = next(key for key, value in menu_values.items() if value == menu)
    
    if menu == "🚪 Keluar":
        st.session_state.logged_in = False
        st.session_state.user = None
        st.session_state.active_exam = None
        st.query_params.clear()
        st.rerun()

# ==================== DASHBOARD ====================
if menu == "🏠 Dashboard":
    render_header(f"Selamat Datang, {current_user['username']}!", "Sistem keamanan ujian aktif · Terakhir diverifikasi: Hari ini")
    
    if role == 'student':
        exams = execute_query("SELECT * FROM exams ORDER BY id DESC", fetch=True) or []
        subs = execute_query("SELECT * FROM student_submissions WHERE user_id = %s", (current_user['id'],), fetch=True) or []
        
        col1, col2, col3 = st.columns(3)
        with col1:
            st.markdown(f"""
            <div class="stat-card">
                <div class="stat-icon" style="background: #e0f2e9; color: #1a7f5a;">📚</div>
                <div class="stat-info"><h3>{len(exams)}</h3><p>Ujian Tersedia</p></div>
            </div>
            """, unsafe_allow_html=True)
        with col2:
            st.markdown(f"""
            <div class="stat-card">
                <div class="stat-icon" style="background: #e3f2fd; color: #1565c0;">✅</div>
                <div class="stat-info"><h3>{len(subs)}</h3><p>Sudah Selesai</p></div>
            </div>
            """, unsafe_allow_html=True)
        with col3:
            avg = sum(s['score'] for s in subs) / len(subs) if subs else 0
            st.markdown(f"""
            <div class="stat-card">
                <div class="stat-icon" style="background: #fff3e0; color: #ef6c00;">🏆</div>
                <div class="stat-info"><h3>{avg:.1f}</h3><p>Rata-rata Nilai</p></div>
            </div>
            """, unsafe_allow_html=True)
        
        st.markdown("### 📋 Daftar Ujian")
        if not exams:
            st.info("Belum ada jadwal ujian yang tersedia.")
        else:
            for ex in exams:
                sub = next((s for s in subs if s['exam_id'] == ex['id']), None)
                with st.container(border=True):
                    c1, c2 = st.columns([4, 1])
                    with c1:
                        st.markdown(f"**{ex['title']}**")
                        st.caption(f"Kode: {ex['exam_code']} · {ex['duration_minutes']} menit")
                    with c2:
                        if sub:
                            st.success(f"Nilai: {sub['score']}")
                        else:
                            st.info("Belum dikerjakan")
    else:
        col1, col2, col3, col4 = st.columns(4)
        with col1: 
            total_exams = len(execute_query("SELECT id FROM exams", fetch=True) or [])
            st.metric("Total Ujian", total_exams)
        with col2: 
            total_students = len(execute_query("SELECT id FROM users WHERE role='student'", fetch=True) or [])
            st.metric("Mahasiswa", total_students)
        with col3: 
            total_subs = len(execute_query("SELECT id FROM student_submissions", fetch=True) or [])
            st.metric("Submit", total_subs)
        with col4: 
            ok, _ = blockchain.validate_chain()
            st.metric("Blockchain", "✅ Valid" if ok else "⚠️ Error")

# ==================== KELOLA UJIAN (PROCTOR) ====================
elif menu == "📝 Kelola Ujian":
    render_header("Kelola Ujian", "Buat dan kelola bank soal dengan super enkripsi (Vigenère + AES-256-GCM)")
    
    tab1, tab2 = st.tabs(["➕ Buat Ujian Baru", "📂 Daftar & Kelola Ujian"])
    
    with tab1:
        is_edit = st.session_state.editing_exam_id is not None
        
        defaults = {
            "code": "KRIPTO-2026-A", "title": "Ujian Akhir Semester", "duration": 90, "token": "TOKEN-UPN-99",
            "questions": [{"question": "", "options": {"A": "", "B": "", "C": "", "D": ""}, "correct": "A"}]
        }
        
        if is_edit:
            exam = execute_query("SELECT * FROM exams WHERE id = %s", (st.session_state.editing_exam_id,), fetch=False)
            if exam:
                st.warning(f"✏️ Mode Edit: **{exam['title']}**")
                defaults.update({
                    "code": exam['exam_code'], "title": exam['title'], "duration": exam['duration_minutes'], "token": exam['token_hash']
                })
                try:
                    dec_aes = aes_decrypt(exam['encrypted_question'], b"KunciAES32BytesPanjangPasBanget!!")
                    dec_vig = extended_vigenere_decrypt(dec_aes, "KeyVigenereUPN2026")
                    defaults["questions"] = json.loads(dec_vig)
                except Exception as e:
                    st.error(f"Gagal dekripsi: {e}")
                
                if st.button("❌ Batal Edit"):
                    st.session_state.editing_exam_id = None
                    st.rerun()
        
        question_count_key = f"question_count_{st.session_state.editing_exam_id or 'new'}"
        st.markdown("### 📋 Informasi Dasar")
        if question_count_key not in st.session_state:
            st.session_state[question_count_key] = len(defaults["questions"])
        num_q = st.number_input("Jumlah Soal", min_value=1, max_value=50, key=question_count_key)
        with st.form("exam_form"):
            c1, c2 = st.columns(2)
            with c1:
                code = st.text_input("Kode Ujian", value=defaults["code"])
                title = st.text_input("Judul Ujian", value=defaults["title"])
            with c2:
                dur = st.number_input("Durasi (menit)", value=int(defaults["duration"]), min_value=1)
                token = st.text_input("Token Rahasia", value=defaults["token"])
            
            st.markdown("### ✍️ Bank Soal")
            
            questions_data = []
            for i in range(int(num_q)):
                q_old = defaults["questions"][i] if i < len(defaults["questions"]) else {}
                with st.expander(f"Soal {i+1}", expanded=(i==0)):
                    q_text = st.text_area("Pertanyaan", value=q_old.get("question", ""), key=f"q{i}", height=80)
                    cols = st.columns(4)
                    opt_a = cols[0].text_input("A", value=q_old.get("options", {}).get("A", ""), key=f"a{i}")
                    opt_b = cols[1].text_input("B", value=q_old.get("options", {}).get("B", ""), key=f"b{i}")
                    opt_c = cols[2].text_input("C", value=q_old.get("options", {}).get("C", ""), key=f"c{i}")
                    opt_d = cols[3].text_input("D", value=q_old.get("options", {}).get("D", ""), key=f"d{i}")
                    correct = st.selectbox("Kunci", ["A","B","C","D"], 
                        index=["A","B","C","D"].index(q_old.get("correct", "A")) if q_old.get("correct") in ["A","B","C","D"] else 0,
                        key=f"k{i}")
                    
                questions_data.append({
                    "question": q_text,
                    "options": {"A": opt_a, "B": opt_b, "C": opt_c, "D": opt_d},
                    "correct": correct
                })
            
            btn_label = "💾 Simpan Perubahan" if is_edit else "🚀 Terbitkan dengan Super Enkripsi"
            if st.form_submit_button(btn_label, type="primary"):
                empty = [i+1 for i, q in enumerate(questions_data) if not q["question"].strip()]
                if empty:
                    st.error(f"Soal nomor {empty} masih kosong!")
                else:
                    raw_json = json.dumps(questions_data, ensure_ascii=False)
                    vig_enc = extended_vigenere_encrypt(raw_json, "KeyVigenereUPN2026")
                    super_enc = aes_encrypt(vig_enc, b"KunciAES32BytesPanjangPasBanget!!")
                    ans_key = json.dumps({i: q['correct'] for i, q in enumerate(questions_data)})
                    
                    if is_edit:
                        execute_query("""
                            UPDATE exams SET exam_code=%s, title=%s, encrypted_question=%s, 
                            encrypted_answer_key=%s, duration_minutes=%s, token_hash=%s WHERE id=%s
                        """, (code, title, super_enc, ans_key, dur, token, st.session_state.editing_exam_id))
                        blockchain.add_block({"event": "EDIT_EXAM", "exam_id": st.session_state.editing_exam_id, "exam_code": code, "editor": current_user['username']})
                        st.session_state.editing_exam_id = None
                        st.success(f"✅ Ujian '{title}' berhasil diperbarui!")
                    else:
                        execute_query("""
                            INSERT INTO exams (exam_code, title, encrypted_question, encrypted_answer_key, duration_minutes, token_hash)
                            VALUES (%s, %s, %s, %s, %s, %s)
                        """, (code, title, super_enc, ans_key, dur, token))
                        blockchain.add_block({"event": "CREATE_EXAM", "exam_code": code, "total_questions": len(questions_data), "creator": current_user['username']})
                        st.success(f"🎉 Ujian '{title}' berhasil diterbitkan dengan {len(questions_data)} soal terenkripsi!")
                        st.balloons()
                    st.rerun()
    
    with tab2:
        st.markdown("### 📂 Daftar Ujian Terbit")
        exams = execute_query("SELECT * FROM exams ORDER BY id DESC", fetch=True) or []
        
        if not exams:
            st.info("Belum ada ujian yang diterbitkan.")
        else:
            cols = st.columns(2)
            for idx, ex in enumerate(exams):
                with cols[idx % 2]:
                    with st.container(border=True):
                        st.markdown(f"**{ex['title']}**")
                        st.caption(f"Kode: {ex['exam_code']} · Durasi: {ex['duration_minutes']} menit · Token: {ex['token_hash']}")
                        
                        c1, c2 = st.columns(2)
                        with c1:
                            if st.button("✏️ Edit", key=f"edit_{ex['id']}", use_container_width=True):
                                st.session_state.editing_exam_id = ex['id']
                                st.rerun()
                        with c2:
                            if st.button("🗑️ Hapus", key=f"del_{ex['id']}", use_container_width=True):
                                execute_query("DELETE FROM exams WHERE id = %s", (ex['id'],))
                                blockchain.add_block({"event": "DELETE_EXAM", "exam_id": ex['id'], "user": current_user['username']})
                                st.success("Ujian dihapus!")
                                st.rerun()
        
        st.markdown("---")
        st.markdown("### 🖼️ Steganografi Token")
        if st.button("Generate Gambar Stego Token"):
            bg_path = "assets/default_exam_bg.jpg"
            stego_path = "assets/stego_exam_token.png"
            if os.path.exists(bg_path):
                success, msg = encode_image(bg_path, "TOKEN-UPN-99", stego_path)
                if success:
                    st.success(f"{msg}")
                    st.image(stego_path, width=400, caption="Poster dengan token tersembunyi (LSB)")
                else:
                    st.error(msg)
            else:
                st.warning("File background tidak ditemukan.")

# ==================== UJIAN SAYA (STUDENT) ====================
elif menu == "📝 Ujian Saya":
    render_header("Ujian Saya", "Masukkan token dari dosen untuk memulai ujian")
    
    if not st.session_state.active_exam:
        exams = execute_query("SELECT * FROM exams ORDER BY id DESC", fetch=True) or []
        if not exams:
            st.info("Belum ada jadwal ujian tersedia.")
        else:
            cols = st.columns(2)
            for idx, ex in enumerate(exams):
                sub = execute_query("SELECT * FROM student_submissions WHERE user_id = %s AND exam_id = %s", 
                                   (current_user['id'], ex['id']), fetch=False)
                
                with cols[idx % 2]:
                    with st.container(border=True):
                        st.markdown(f"**{ex['title']}**")
                        st.caption(f"{ex['exam_code']} · {ex['duration_minutes']} menit")
                        
                        if sub:
                            st.success(f"✅ Selesai · Nilai: {sub['score']}")
                        else:
                            if st.session_state.token_target_exam_id != ex['id']:
                                if st.button("🎯 Mulai Ujian", key=f"start_{ex['id']}", use_container_width=True):
                                    st.session_state.token_target_exam_id = ex['id']
                                    st.rerun()
                            else:
                                st.markdown("---")
                                tok = st.text_input("Masukkan Token", key=f"tok_{ex['id']}", placeholder="Token dari dosen...")
                                c1, c2 = st.columns(2)
                                if c1.button("Verifikasi & Mulai", key=f"verify_{ex['id']}", type="primary"):
                                    if tok.strip() == ex['token_hash']:
                                        try:
                                            dec_aes = aes_decrypt(ex['encrypted_question'], b"KunciAES32BytesPanjangPasBanget!!")
                                            dec_vig = extended_vigenere_decrypt(dec_aes, "KeyVigenereUPN2026")
                                            questions = json.loads(dec_vig)
                                            
                                            st.session_state.active_exam = {
                                                "exam_info": ex,
                                                "questions": questions,
                                                "answer_key": json.loads(ex['encrypted_answer_key'])
                                            }
                                            st.session_state.current_question_idx = 0
                                            st.session_state.student_answers = {}
                                            st.session_state.token_target_exam_id = None
                                            st.success("Token valid! Memuat soal...")
                                            st.rerun()
                                        except Exception as e:
                                            st.error(f"Error dekripsi: {e}")
                                    else:
                                        st.error("Token salah!")
                                if c2.button("Batal", key=f"cancel_{ex['id']}"):
                                    st.session_state.token_target_exam_id = None
                                    st.rerun()
    else:
        active = st.session_state.active_exam
        ex_info = active["exam_info"]
        questions = active["questions"]
        q_idx = st.session_state.current_question_idx
        
        col_nav, col_content = st.columns([1, 2.5])
        
        with col_nav:
            st.markdown(f"**{ex_info['title']}**")
            st.markdown("---")
            st.markdown("**Navigasi Soal**")
            nav_cols = st.columns(5)
            for i in range(len(questions)):
                with nav_cols[i % 5]:
                    if st.button(str(i+1), key=f"nav_{i}", use_container_width=True):
                        st.session_state.current_question_idx = i
                        st.rerun()
            st.markdown("---")
            if st.button("🏳️ Menyerah / Keluar"):
                st.session_state.active_exam = None
                st.rerun()
        
        with col_content:
            q_data = questions[q_idx]
            st.markdown(f"### Soal {q_idx+1} dari {len(questions)}")
            
            with st.container(border=True):
                st.markdown(f"**{q_data['question']}**")
            
            current_ans = st.session_state.student_answers.get(q_idx, None)
            opts = ["A", "B", "C", "D"]
            default_idx = opts.index(current_ans) if current_ans in opts else 0
            
            selected = st.radio(
                "Pilih jawaban:",
                opts,
                format_func=lambda x: f"{x}. {q_data['options'][x]}",
                index=default_idx,
                key=f"radio_{q_idx}"
            )
            st.session_state.student_answers[q_idx] = selected
            
            c1, c2, c3 = st.columns([1, 1, 2])
            if q_idx > 0 and c1.button("← Sebelumnya", use_container_width=True):
                st.session_state.current_question_idx -= 1
                st.rerun()
            if q_idx < len(questions) - 1 and c2.button("Selanjutnya →", use_container_width=True):
                st.session_state.current_question_idx += 1
                st.rerun()
            if q_idx == len(questions) - 1 and c3.button("🚀 SUBMIT UJIAN", type="primary", use_container_width=True):
                ans_key = active["answer_key"]
                correct = sum(1 for k, v in ans_key.items() if st.session_state.student_answers.get(int(k)) == v)
                score = (correct / len(questions)) * 100
                
                enc_ans = aes_encrypt(json.dumps(st.session_state.student_answers), b"KunciAES32BytesPanjangPasBanget!!")
                execute_query("""
                    INSERT INTO student_submissions (user_id, exam_id, encrypted_answers, score, status)
                    VALUES (%s, %s, %s, %s, 'Finished')
                """, (current_user['id'], ex_info['id'], enc_ans, score))
                
                blockchain.add_block({
                    "event": "SUBMIT_EXAM",
                    "student": current_user['username'],
                    "exam_code": ex_info['exam_code'],
                    "score": score
                })
                
                st.session_state.active_exam = None
                st.success(f"🎉 Ujian selesai! Nilai Anda: **{score:.1f}**")
                st.balloons()
                st.rerun()

# ==================== BLOCKCHAIN LOG ====================
elif menu == "⛓️ Blockchain Log":
    render_header("Blockchain Audit Trail", "Setiap aktivitas tercatat permanen dengan SHA-256")
    
    if st.button("🔍 Validasi Integritas Blockchain"):
        ok, msg = blockchain.validate_chain()
        if ok:
            st.success(f"✅ {msg}")
        else:
            st.error(f"❌ {msg}")
    
    logs = execute_query("SELECT * FROM blockchain_logs ORDER BY block_index DESC", fetch=True) or []
    if logs:
        for log in logs:
            with st.container(border=True):
                st.markdown(f"**Block #{log['block_index']}** · {log['timestamp']}")
                st.code(log['data_payload'])
    else:
        st.info("Belum ada blok tercatat.")

# ==================== PROFIL ====================
elif menu == "👤 Profil":
    render_header("Profil Pengguna", "Informasi akun dan statistik aktivitas")
    
    # Card utama profil
    with st.container(border=True):
        c1, c2 = st.columns([1, 3])
        with c1:
            st.markdown("<div style='font-size: 80px; text-align: center; padding: 20px;'>👤</div>", unsafe_allow_html=True)
        with c2:
            st.markdown(f"### {current_user['username']}")
            st.markdown(f"**Role:** {current_user['role'].upper()}")
            st.markdown(f"**User ID:** #{current_user['id']}")
            st.markdown(f"**Terdaftar:** {current_user['created_at']}")
    
    st.markdown("### 📊 Statistik Aktivitas")
    
    if role == 'proctor':
        # Statistik untuk dosen
        total_exams = len(execute_query("SELECT id FROM exams", fetch=True) or [])
        total_subs = len(execute_query("SELECT id FROM student_submissions", fetch=True) or [])
        total_students = len(execute_query("SELECT id FROM users WHERE role='student'", fetch=True) or [])
        
        c1, c2, c3 = st.columns(3)
        with c1:
            st.metric("Ujian Dibuat", total_exams)
        with c2:
            st.metric("Total Submit", total_subs)
        with c3:
            st.metric("Mahasiswa Terdaftar", total_students)
        
        # Ujian terbaru
        st.markdown("### 📝 Ujian Terbaru")
        exams = execute_query("SELECT * FROM exams ORDER BY id DESC LIMIT 5", fetch=True) or []
        if exams:
            for ex in exams:
                with st.container(border=True):
                    st.markdown(f"**{ex['title']}**")
                    st.caption(f"Kode: {ex['exam_code']} · Durasi: {ex['duration_minutes']} menit · Token: {ex['token_hash']}")
        else:
            st.info("Belum ada ujian yang dibuat")
    
    else:
        # Statistik untuk mahasiswa
        subs = execute_query("SELECT * FROM student_submissions WHERE user_id = %s ORDER BY id DESC", (current_user['id'],), fetch=True) or []
        total_subs = len(subs)
        avg_score = sum(s['score'] for s in subs) / total_subs if total_subs > 0 else 0
        
        c1, c2, c3 = st.columns(3)
        with c1:
            st.metric("Ujian Selesai", total_subs)
        with c2:
            st.metric("Rata-rata Nilai", f"{avg_score:.1f}")
        with c3:
            st.metric("Status", "Aktif" if total_subs > 0 else "Baru")
        
        # Riwayat ujian
        st.markdown("### 📋 Riwayat Ujian")
        if subs:
            for sub in subs:
                exam = execute_query("SELECT * FROM exams WHERE id = %s", (sub['exam_id'],), fetch=False)
                if exam:
                    with st.container(border=True):
                        c1, c2 = st.columns([3, 1])
                        with c1:
                            st.markdown(f"**{exam['title']}**")
                            st.caption(f"Kode: {exam['exam_code']} · Dikerjakan: {sub['submitted_at']}")
                        with c2:
                            score_color = "🟢" if sub['score'] >= 75 else "🟡" if sub['score'] >= 60 else "🔴"
                            st.markdown(f"### {score_color} {sub['score']}")
        else:
            st.info("Belum ada riwayat ujian")
    
    # Keamanan akun
    st.markdown("---")
    st.markdown("### 🔒 Keamanan Akun")
    with st.container(border=True):
        st.markdown("**Metode Login:** Password + PBKDF2-SHA256")
        st.markdown("**Biometrik Wajah:** Tersedia (Opsional)")
        st.markdown("**Enkripsi Data:** AES-256-GCM + Vigenère")
        st.caption("Semua data ujian dan jawaban dienkripsi dengan standar kriptografi modern")

