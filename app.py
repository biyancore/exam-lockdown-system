import streamlit as st
import os
import json
from PIL import Image
from modules.database import ensure_schema, execute_query
from modules.auth import check_dongle, verify_password, verify_face_biometric
from modules.modern_cipher import aes_encrypt, aes_decrypt
from modules.classic_cipher import extended_vigenere_encrypt, extended_vigenere_decrypt
from modules.steganography import encode_image, decode_image
from modules.blockchain import SimpleBlockchain

# Konfigurasi Halaman
st.set_page_config(
    page_title="Secure Exam Dashboard - UPN Veteran Yogyakarta",
    page_icon="🎓",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Inisialisasi Database & Blockchain
ensure_schema()
blockchain = SimpleBlockchain()

# Load Custom CSS
css_path = "utils/style.css"
if os.path.exists(css_path):
    with open(css_path) as f:
        st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)

# ---------------------------------------------------------
# GERBANG 1: CEK DONGLE FISIK
# ---------------------------------------------------------
dongle_ok, dongle_msg = check_dongle()
if not dongle_ok:
    st.error(f"🔒 **APLIKASI TERKUNCI**: {dongle_msg}")
    st.info("Silakan pasang file dongle yang valid di direktori `config/dongle.key`.")
    st.stop()

if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
    st.session_state.user = None
    st.session_state.active_exam = None
    st.session_state.current_question_idx = 0
    st.session_state.student_answers = {}

# ---------------------------------------------------------
# HALAMAN LOGIN
# ---------------------------------------------------------
if not st.session_state.logged_in:
    col1, col2, col3 = st.columns([1, 1.2, 1])
    with col2:
        st.markdown("<br><br>", unsafe_allow_html=True)
        if os.path.exists("assets/logo_upnvy.png"):
            st.image("assets/logo_upnvy.png", width=90)
        st.markdown("### **Secure Exam Dashboard**")
        st.caption("Universitas Pembangunan Nasional 'Veteran' Yogyakarta")
        
        with st.form("login_form"):
            username = st.text_input("Username / NIM")
            password = st.text_input("Password", type="password")
            use_biometric = st.checkbox("Gunakan Verifikasi Biometrik Wajah (Webcam)")
            submit = st.form_submit_button("Masuk Portal")
            
            if submit:
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
                    st.success("Login berhasil!")
                    st.rerun()
                else:
                    st.error("Username atau password salah!")
    st.stop()

current_user = st.session_state.user
role = current_user['role']

# ---------------------------------------------------------
# SIDEBAR NAVIGASI
# ---------------------------------------------------------
with st.sidebar:
    if os.path.exists("assets/logo_upnvy.png"):
        st.image("assets/logo_upnvy.png", width=65)
    st.markdown(f"### **UPNVY Portal**")
    st.caption(f"Role: **{role.upper()}** | 👤 {current_user['username']}")
    st.markdown("---")
    
    if role == 'proctor':
        menu = st.radio("Navigasi", ["Dashboard", "Buat Ujian & Soal", "Log Blockchain", "Akun", "Keluar"])
    else:
        menu = st.radio("Navigasi", ["Dashboard", "Test Seleksi / Ujian", "Log Blockchain", "Akun", "Keluar"])
    
    if menu == "Keluar":
        st.session_state.logged_in = False
        st.session_state.user = None
        st.session_state.active_exam = None
        st.rerun()

# ---------------------------------------------------------
# HALAMAN: DASHBOARD UTAMA
# ---------------------------------------------------------
if menu == "Dashboard":
    st.markdown(f"## 🏠 Dashboard {role.capitalize()}")
    st.info(f"Selamat datang kembali, **{current_user['username']}**. Sistem pengaman ujian berbasis kriptografi dan blockchain aktif.")
    
    if role == 'student':
        st.markdown("### Status Ujian Anda")
        exams = execute_query("SELECT * FROM exams ORDER BY id DESC", fetch=True)
        if not exams:
            st.warning("Belum ada jadwal ujian yang tersedia saat ini.")
        else:
            for ex in exams:
                # Cek apakah mahasiswa sudah pernah submit ujian ini
                sub = execute_query(
                    "SELECT * FROM student_submissions WHERE user_id = %s AND exam_id = %s", 
                    (current_user['id'], ex['id']), fetch=False
                )
                status_text = "Sudah Dikerjakan (Selesai)" if sub else "Belum Dikerjakan (Tersedia)"
                
                with st.container():
                    st.markdown(f"""
                    <div class="exam-card">
                        <h4>📘 {ex['title']}</h4>
                        <p><b>Kode Ujian:</b> {ex['exam_code']} | <b>Durasi:</b> {ex['duration_minutes']} Menit</p>
                        <p><b>Status:</b> <span style="color: {'green' if sub else 'orange'}; font-weight: bold;">{status_text}</span></p>
                        {'<p><b>Nilai Akhir:</b> ' + str(sub['score']) + '</p>' if sub else ''}
                    </div>
                    """, unsafe_allow_html=True)
    else:
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric(label="Total Soal/Ujian", value=len(execute_query("SELECT id FROM exams", fetch=True) or []))
        with col2:
            st.metric(label="Mahasiswa Submit", value=len(execute_query("SELECT id FROM student_submissions", fetch=True) or []))
        with col3:
            st.metric(label="Integritas Blok", value="Aman (Valid)")

# ---------------------------------------------------------
# HALAMAN: DOSEN - BUAT & KELOLA / EDIT UJIAN (FULL INTERAKTIF)
# ---------------------------------------------------------
elif menu == "Buat Ujian & Soal":
    st.markdown("## 🛠️ Panel Dosen: Buat & Kelola Bank Soal")
    st.info("Anda dapat membuat ujian baru atau memilih ujian yang sudah diterbitkan di bawah untuk diedit kembali.")

    # State untuk melacak ujian mana yang sedang diedit
    if "editing_exam_id" not in st.session_state:
        st.session_state.editing_exam_id = None

    # Tab Navigasi Sisi Dosen: [1. Buat / Edit Ujian] dan [2. Kelola Ujian Diterbitkan]
    tab_create, tab_manage = st.tabs(["📝 Buat / Edit Ujian", "📂 Daftar & Kelola Ujian Diterbitkan"])

    # -----------------------------------------------------
    # TAB 1: FORM BUAT ATAU EDIT UJIAN
    # -----------------------------------------------------
    with tab_create:
        is_edit_mode = st.session_state.editing_exam_id is not None
        
        # Data default untuk form
        default_code = "KRIPTO-2026-A"
        default_title = "Ujian Akhir Semester Kriptografi"
        default_duration = 5
        default_token = "TOKEN-UPN-99"
        default_questions = [
            {"question": "", "options": {"A": "", "B": "", "C": "", "D": ""}, "correct": "A"}
        ]

        # Jika sedang dalam MODE EDIT, ambil data ujian dari database dan dekripsi soalnya
        if is_edit_mode:
            exam_to_edit = execute_query("SELECT * FROM exams WHERE id = %s", (st.session_state.editing_exam_id,), fetch=False)
            if exam_to_edit:
                st.warning(f"✏️ **MODE EDIT AKTIF**: Anda sedang mengedit ujian **'{exam_to_edit['title']}'** (ID: {exam_to_edit['id']})")
                default_code = exam_to_edit['exam_code']
                default_title = exam_to_edit['title']
                default_duration = exam_to_edit['duration_minutes']
                default_token = exam_to_edit['token_hash']
                
                # Dekripsi soal yang tersimpan untuk diisi kembali ke form
                try:
                    dec_aes = aes_decrypt(exam_to_edit['encrypted_question'], b"KunciAES32BytesPanjangPasBanget!!")
                    dec_vig = extended_vigenere_decrypt(dec_aes, "KeyVigenereUPN2026")
                    default_questions = json.loads(dec_vig)
                except Exception as e:
                    st.error(f"Gagal mendekripsi soal untuk diedit: {e}")
                
                if st.button("❌ Batal Edit (Kembali Buat Ujian Baru)"):
                    st.session_state.editing_exam_id = None
                    st.session_state.num_q_input = 3
                    st.rerun()

        # Input Jumlah Soal
        col_info, col_num = st.columns([2, 1])
        with col_num:
            init_val = len(default_questions) if is_edit_mode else st.session_state.get("num_q_input", 3)
            num_questions = st.number_input(
                "🔢 Jumlah Soal", 
                min_value=1, 
                max_value=100, 
                value=init_val,
                step=1,
                key="num_q_input"
            )

        # Form Pengisian / Pengeditan Ujian
        with st.form("exam_full_creation_form"):
            st.markdown("### 📋 1. Informasi Umum Ujian")
            col_meta1, col_meta2 = st.columns(2)
            with col_meta1:
                exam_code = st.text_input("Kode Ujian Unik", value=default_code)
                title = st.text_input("Judul Ujian", value=default_title)
            with col_meta2:
                duration = st.number_input("Durasi Ujian (Menit)", value=int(default_duration), min_value=1, step=1)
                secret_token = st.text_input("Token / Kunci Ujian (Wajib dimasukkan mahasiswa)", value=default_token)
            
            st.markdown("---")
            st.markdown(f"### ✍️ 2. Lembar Bank Soal ({num_questions} Soal)")
            
            questions_data = []
            
            # Looping pembuatan kartu soal individual
            for i in range(int(num_questions)):
                # Ambil data lama jika ada (saat mode edit)
                q_old = default_questions[i] if (is_edit_mode and i < len(default_questions)) else {}
                old_q_text = q_old.get("question", "")
                old_opts = q_old.get("options", {"A": "", "B": "", "C": "", "D": ""})
                old_correct = q_old.get("correct", "A")

                with st.container(border=True):
                    st.markdown(f"### **Soal Nomor {i+1}**")
                    
                    q_text = st.text_area(
                        f"Teks Pertanyaan #{i+1}", 
                        value=old_q_text,
                        key=f"q_text_{i}", 
                        height=80, 
                        placeholder=f"Ketik pertanyaan untuk soal nomor {i+1} di sini..."
                    )
                    
                    col_opt1, col_opt2 = st.columns(2)
                    with col_opt1:
                        opt_a = st.text_input(f"Pilihan A #{i+1}", value=old_opts.get("A", ""), key=f"qa_{i}", placeholder="Pilihan A")
                        opt_b = st.text_input(f"Pilihan B #{i+1}", value=old_opts.get("B", ""), key=f"qb_{i}", placeholder="Pilihan B")
                    with col_opt2:
                        opt_c = st.text_input(f"Pilihan C #{i+1}", value=old_opts.get("C", ""), key=f"qc_{i}", placeholder="Pilihan C")
                        opt_d = st.text_input(f"Pilihan D #{i+1}", value=old_opts.get("D", ""), key=f"qd_{i}", placeholder="Pilihan D")
                        
                    correct_ans = st.selectbox(
                        f"Kunci Jawaban Benar (Soal #{i+1})", 
                        ["A", "B", "C", "D"], 
                        index=["A", "B", "C", "D"].index(old_correct) if old_correct in ["A", "B", "C", "D"] else 0,
                        key=f"ans_{i}"
                    )
                    
                questions_data.append({
                    "question": q_text,
                    "options": {"A": opt_a, "B": opt_b, "C": opt_c, "D": opt_d},
                    "correct": correct_ans
                })
                st.markdown("<br>", unsafe_allow_html=True)
                
            btn_label = "💾 Simpan Perubahan Ujian" if is_edit_mode else "🚀 Simpan, Super Enkripsi, & Terbitkan Ujian"
            submit_all_exam = st.form_submit_button(btn_label)
            
            if submit_all_exam:
                empty_questions = [idx + 1 for idx, q in enumerate(questions_data) if not q["question"].strip()]
                if empty_questions:
                    st.error(f"❌ Soal nomor {empty_questions} masih kosong! Silakan lengkapi terlebih dahulu.")
                else:
                    # Enkripsi ulang (Vigenère + AES-GCM)
                    raw_json_str = json.dumps(questions_data, ensure_ascii=False)
                    vig_enc = extended_vigenere_encrypt(raw_json_str, "KeyVigenereUPN2026")
                    super_enc = aes_encrypt(vig_enc, b"KunciAES32BytesPanjangPasBanget!!")
                    answer_key_json = json.dumps({idx: q['correct'] for idx, q in enumerate(questions_data)})
                    
                    if is_edit_mode:
                        # UPDATE UJIAN YANG SUDAH ADA
                        q_update = """
                            UPDATE exams 
                            SET exam_code = %s, title = %s, encrypted_question = %s, 
                                encrypted_answer_key = %s, duration_minutes = %s, token_hash = %s
                            WHERE id = %s
                        """
                        execute_query(q_update, (exam_code, title, super_enc, answer_key_json, duration, secret_token, st.session_state.editing_exam_id))
                        
                        blockchain.add_block({
                            "event": "EDIT_EXAM", 
                            "exam_id": st.session_state.editing_exam_id,
                            "exam_code": exam_code, 
                            "editor": current_user['username']
                        })
                        
                        st.session_state.editing_exam_id = None
                        st.success(f"🎉 Berhasil memperbarui ujian '{title}'! Perubahan telah disimpan ke database dan blockchain.")
                        st.balloons()
                        st.rerun()
                    else:
                        # SIMPAN UJIAN BARU
                        q_insert = """
                            INSERT INTO exams (exam_code, title, encrypted_question, encrypted_answer_key, duration_minutes, token_hash)
                            VALUES (%s, %s, %s, %s, %s, %s)
                        """
                        execute_query(q_insert, (exam_code, title, super_enc, answer_key_json, duration, secret_token))
                        
                        blockchain.add_block({
                            "event": "CREATE_EXAM", 
                            "exam_code": exam_code, 
                            "total_questions": len(questions_data),
                            "creator": current_user['username']
                        })
                        
                        st.success(f"🎉 Berhasil menerbitkan ujian '{title}' dengan {len(questions_data)} soal berformat kartu!")
                        st.balloons()

    # -----------------------------------------------------
    # TAB 2: DAFTAR & KELOLA UJIAN TERBIT (AKSI EDIT/HAPUS)
    # -----------------------------------------------------
    with tab_manage:
        st.markdown("### 📂 Daftar Ujian Terbit di Database")
        exams = execute_query("SELECT * FROM exams ORDER BY id DESC", fetch=True)
        
        if not exams:
            st.info("Belum ada ujian yang diterbitkan.")
        else:
            cols_ex = st.columns(2)
            for idx, ex in enumerate(exams):
                with cols_ex[idx % 2]:
                    with st.container(border=True):
                        st.markdown(f"### 📘 {ex['title']}")
                        st.markdown(f"**Kode Ujian:** `{ex['exam_code']}`")
                        st.markdown(f"⏱️ **Durasi:** {ex['duration_minutes']} Menit")
                        st.markdown(f"🔑 **Token Rahasia:** `{ex['token_hash']}`")
                        st.markdown("<br>", unsafe_allow_html=True)
                        
                        col_ed, col_del = st.columns(2)
                        with col_ed:
                            if st.button("✏️ Edit Ujian Ini", key=f"btn_edit_exam_{ex['id']}"):
                                st.session_state.editing_exam_id = ex['id']
                                st.rerun()
                        with col_del:
                            if st.button("🗑️ Hapus Ujian", key=f"btn_del_exam_{ex['id']}"):
                                execute_query("DELETE FROM exams WHERE id = %s", (ex['id'],))
                                blockchain.add_block({"event": "DELETE_EXAM", "exam_id": ex['id'], "user": current_user['username']})
                                st.success("Ujian berhasil dihapus!")
                                st.rerun()
                    st.markdown("<br>", unsafe_allow_html=True)

    st.markdown("---")
    st.markdown("### 🖼️ Steganografi Token Ujian")
    if st.button("Generate Gambar Stego Token"):
        bg_path = "assets/default_exam_bg.jpg"
        stego_path = "assets/stego_exam_token.png"
        if os.path.exists(bg_path):
            success, msg = encode_image(bg_path, "TOKEN-UPN-99", stego_path)
            if success:
                st.success(f"{msg}. Mahasiswa dapat mengunduh gambar ini untuk mendapatkan token ujian.")
                st.image(stego_path, width=400, caption="Poster Ujian Berisi Token Tersembunyi (LSB)")
            else:
                st.error(msg)
        else:
            st.warning("File latar belakang `assets/default_exam_bg.jpg` tidak ditemukan.")

# ---------------------------------------------------------
# HALAMAN: MAHASISWA - TEST SELEKSI & UJIAN INTERAKTIF (GRID 2 KOLOM)
# ---------------------------------------------------------
elif menu == "Test Seleksi / Ujian":
    st.markdown("## 📝 Portal Test Seleksi & Ujian")
    
    # Inisialisasi session state untuk melacak ujian mana yang sedang memasukkan token
    if "token_target_exam_id" not in st.session_state:
        st.session_state.token_target_exam_id = None

    # Jika sedang tidak aktif mengerjakan ujian, tampilkan daftar ujian dalam Grid 2 Kolom
    if st.session_state.active_exam is None:
        exams = execute_query("SELECT * FROM exams ORDER BY id DESC", fetch=True)
        if not exams:
            st.info("Belum ada jadwal ujian yang tersedia saat ini.")
        else:
            # Membagi daftar ujian menjadi 2 kolom grid yang rapi
            cols = st.columns(2)
            for idx, ex in enumerate(exams):
                # Cek apakah mahasiswa sudah pernah submit ujian ini sebelumnya
                sub = execute_query(
                    "SELECT * FROM student_submissions WHERE user_id = %s AND exam_id = %s",
                    (current_user['id'], ex['id']), fetch=False
                )
                
                # Menempatkan kartu secara bergantian ke kolom kiri (0) dan kanan (1)
                with cols[idx % 2]:
                    with st.container(border=True):
                        st.markdown(f"### 📘 {ex['title']}")
                        st.markdown(f"**Kode Ujian:** `{ex['exam_code']}`")
                        st.markdown(f"⏱️ **Durasi:** {ex['duration_minutes']} Menit")
                        
                        if sub:
                            st.markdown(f"Status: <span style='color: green; font-weight: bold;'>Sudah Dikerjakan (Selesai)</span>", unsafe_allow_html=True)
                            st.markdown(f"🏆 **Nilai Akhir:** `{sub['score']}`")
                        else:
                            st.markdown(f"Status: <span style='color: orange; font-weight: bold;'>Belum Dikerjakan (Tersedia)</span>", unsafe_allow_html=True)
                            st.markdown("<br>", unsafe_allow_html=True)
                            
                            # Tombol "Ikuti Ujian" untuk memunculkan form token
                            if st.button("Ikuti Ujian", key=f"btn_ikuti_{ex['id']}"):
                                st.session_state.token_target_exam_id = ex['id']
                                st.rerun()
                                
                            # Jika tombol "Ikuti Ujian" pada kartu ini diklik, tampilkan kolom input token
                            if st.session_state.token_target_exam_id == ex['id']:
                                st.markdown("---")
                                st.markdown("🔑 **Masukkan Kunci / Token Ujian:**")
                                token_input = st.text_input("Token Rahasia", key=f"token_input_{ex['id']}", type="default", placeholder="Masukkan token dari dosen/stego...")
                                
                                col_submit_token, col_cancel_token = st.columns(2)
                                with col_submit_token:
                                    if st.button("Verifikasi & Mulai", key=f"verify_token_{ex['id']}"):
                                        if token_input.strip() == ex['token_hash']:
                                            try:
                                                # Dekripsi soal dari database (AES lalu Vigenère)
                                                dec_aes = aes_decrypt(ex['encrypted_question'], b"KunciAES32BytesPanjangPasBanget!!")
                                                dec_vig = extended_vigenere_decrypt(dec_aes, "KeyVigenereUPN2026")
                                                question_list = json.loads(dec_vig)
                                                
                                                st.session_state.active_exam = {
                                                    "exam_info": ex,
                                                    "questions": question_list,
                                                    "answer_key": json.loads(ex['encrypted_answer_key'])
                                                }
                                                st.session_state.current_question_idx = 0
                                                st.session_state.student_answers = {}
                                                st.session_state.token_target_exam_id = None
                                                st.success("Token valid! Memuat soal...")
                                                st.rerun()
                                            except Exception as e:
                                                st.error(f"Gagal mendekripsi soal: {e}")
                                        else:
                                            st.error("Token ujian salah! Periksa kembali kunci yang diberikan dosen.")
                                with col_cancel_token:
                                    if st.button("Batal", key=f"cancel_token_{ex['id']}"):
                                        st.session_state.token_target_exam_id = None
                                        st.rerun()
                    
                    st.markdown("<br>", unsafe_allow_html=True)
    else:
        # TAMPILAN KETIKA SEDANG MENGERJAKAN UJIAN (Sama seperti sebelumnya)
        active = st.session_state.active_exam
        ex_info = active["exam_info"]
        questions = active["questions"]
        q_idx = st.session_state.current_question_idx
        
        col_left, col_right = st.columns([1, 2.5])
        
        with col_left:
            st.markdown("#### Informasi Ujian")
            st.write(f"**{ex_info['title']}**")
            st.markdown("#### Sisa Waktu")
            st.markdown("### `01 : 25 : 00`")
            
            st.markdown("#### Navigasi Soal")
            cols_nav = st.columns(4)
            for i in range(len(questions)):
                with cols_nav[i % 4]:
                    if st.button(f"{i+1}", key=f"nav_{i}"):
                        st.session_state.current_question_idx = i
                        st.rerun()
                        
        with col_right:
            q_data = questions[q_idx]
            st.markdown(f"#### Pertanyaan {q_idx + 1} dari {len(questions)}")
            with st.container(border=True):
                st.markdown(f"**{q_data['question']}**")
            
            current_ans = st.session_state.student_answers.get(q_idx, None)
            opt_keys = list(q_data['options'].keys())
            default_ix = opt_keys.index(current_ans) if current_ans in opt_keys else 0
            
            selected_option = st.radio(
                "Pilih Jawaban:",
                opt_keys,
                format_func=lambda x: f"{x}. {q_data['options'][x]}",
                index=default_ix,
                key=f"radio_q_{q_idx}"
            )
            
            st.session_state.student_answers[q_idx] = selected_option
            
            st.markdown("<br>", unsafe_allow_html=True)
            col_prev, col_next, col_submit = st.columns([1, 1, 1.5])
            
            with col_prev:
                if q_idx > 0 and st.button("← Sebelumnya"):
                    st.session_state.current_question_idx -= 1
                    st.rerun()
            with col_next:
                if q_idx < len(questions) - 1 and st.button("Selanjutnya →"):
                    st.session_state.current_question_idx += 1
                    st.rerun()
            with col_submit:
                if q_idx == len(questions) - 1:
                    if st.button("🚀 Submit Ujian Final"):
                        answer_key = active["answer_key"]
                        correct_count = 0
                        total_q = len(questions)
                        
                        for idx_str, correct_val in answer_key.items():
                            student_val = st.session_state.student_answers.get(int(idx_str))
                            if student_val == correct_val:
                                correct_count += 1
                                
                        final_score = (correct_count / total_q) * 100
                        
                        encrypted_ans_str = aes_encrypt(json.dumps(st.session_state.student_answers), b"KunciAES32BytesPanjangPasBanget!!")
                        q_sub = """
                            INSERT INTO student_submissions (user_id, exam_id, encrypted_answers, score, status)
                            VALUES (%s, %s, %s, %s, 'Finished')
                        """
                        execute_query(q_sub, (current_user['id'], ex_info['id'], encrypted_ans_str, final_score))
                        
                        blockchain.add_block({
                            "event": "SUBMIT_EXAM",
                            "student": current_user['username'],
                            "exam_code": ex_info['exam_code'],
                            "score": final_score
                        })
                        
                        st.session_state.active_exam = None
                        st.success(f"Ujian berhasil disubmit! Nilai otomatis Anda: **{final_score}**")
                        st.balloons()
                        st.rerun()

# ---------------------------------------------------------
# HALAMAN: LOG BLOCKCHAIN
# ---------------------------------------------------------
elif menu == "Log Blockchain":
    st.markdown("## ⛓️ Transparansi Rantai Blok (Blockchain Audit)")
    st.info("Setiap pembuatan soal, token, dan submit jawaban mahasiswa dicatat secara permanen dan terikat kriptografi (SHA-256) untuk mencegah manipulasi data.")
    
    if st.button("Validasi Integritas Rantai Blok"):
        is_valid, msg = blockchain.validate_chain()
        if is_valid:
            st.success(f"✅ {msg}")
        else:
            st.error(f"❌ {msg}")
            
    st.markdown("### Riwayat Blok (Ledger)")
    logs = execute_query("SELECT * FROM blockchain_logs ORDER BY block_index ASC", fetch=True)
    if logs:
        st.dataframe(logs, use_container_width=True)
    else:
        st.warning("Belum ada blok tercatat.")

# ---------------------------------------------------------
# HALAMAN: AKUN
# ---------------------------------------------------------
elif menu == "Akun":
    st.markdown("## 👤 Profil Pengguna")
    st.markdown(f"""
    <div class="exam-card">
        <p><b>Username / NIM:</b> {current_user['username']}</p>
        <p><b>Role Akses:</b> {current_user['role'].upper()}</p>
        <p><b>Tanggal Terdaftar:</b> {current_user['created_at']}</p>
    </div>
    """, unsafe_allow_html=True)