"""Halaman Profil + pendaftaran biometrik wajah."""
import streamlit as st

from modules import biometric, session
from modules.auth import verify_password
from modules.database import execute_query
from modules.integrity import check_asset, record
from ui.common import flash, render_header, show_flash


def render(current_user, blockchain, dongle_msg):
    render_header("Profil Pengguna", "Informasi akun, biometrik wajah, dan statistik aktivitas")
    show_flash()
    with st.container(border=True):
        c1, c2 = st.columns([1, 3])
        c1.markdown("<div style='font-size: 80px; text-align: center; padding: 20px;'>👤</div>", unsafe_allow_html=True)
        with c2:
            st.markdown(f"### {current_user['username']}")
            st.markdown(f"**Role:** {current_user['role'].upper()}")
            st.markdown(f"**User ID:** #{current_user['id']}")
            st.markdown(f"**Terdaftar:** {current_user['created_at']}")

    render_biometric(current_user, blockchain)

    st.markdown("### 📊 Statistik Aktivitas")
    if current_user["role"] == "proctor":
        total_exams = len(execute_query("SELECT id FROM exams", fetch=True) or [])
        total_subs = len(execute_query("SELECT id FROM student_submissions", fetch=True) or [])
        total_students = len(execute_query("SELECT id FROM users WHERE role='student'", fetch=True) or [])
        c1, c2, c3 = st.columns(3)
        c1.metric("Ujian Dibuat", total_exams)
        c2.metric("Total Submit", total_subs)
        c3.metric("Mahasiswa Terdaftar", total_students)
        st.markdown("### 📝 Ujian Terbaru")
        exams = execute_query("SELECT * FROM exams ORDER BY id DESC LIMIT 5", fetch=True) or []
        for ex in exams:
            with st.container(border=True):
                st.markdown(f"**{ex['title']}**")
                st.caption(f"Kode: {ex['exam_code']} · Durasi: {ex['duration_minutes']} menit")
        if not exams:
            st.info("Belum ada ujian yang dibuat")
    else:
        subs = execute_query("SELECT * FROM student_submissions WHERE user_id = %s ORDER BY id DESC",
                             (current_user["id"],), fetch=True) or []
        total_subs = len(subs)
        avg_score = sum(float(s["score"]) for s in subs) / total_subs if total_subs else 0
        c1, c2, c3 = st.columns(3)
        c1.metric("Ujian Selesai", total_subs)
        c2.metric("Rata-rata Nilai", f"{avg_score:.1f}")
        c3.metric("Status", "Aktif" if total_subs > 0 else "Baru")
        st.markdown("### 📋 Riwayat Ujian")
        for sub in subs:
            exam = execute_query("SELECT * FROM exams WHERE id = %s", (sub["exam_id"],))
            if not exam:
                continue
            status = check_asset("submission", sub["id"])
            badge = {"valid": "🛡️ Nilai terverifikasi blockchain", "tampered": "❌ Nilai tidak cocok dengan blockchain!",
                     "unrecorded": "⚠️ Nilai belum tercatat di blockchain"}[status]
            with st.container(border=True):
                c1, c2 = st.columns([3, 1])
                c1.markdown(f"**{exam['title']}**")
                c1.caption(f"Kode: {exam['exam_code']} · Dikerjakan: {sub['submitted_at']} · {badge}")
                score = float(sub["score"])
                color = "🟢" if score >= 75 else "🟡" if score >= 60 else "🔴"
                c2.markdown(f"### {color} {sub['score']}")
        if not subs:
            st.info("Belum ada riwayat ujian")

    st.markdown("---")
    st.markdown("### 🔒 Keamanan Akun & Aplikasi")
    with st.container(border=True):
        enrolled = biometric.is_enrolled(current_user["id"])
        st.markdown("**Dongle:** " + dongle_msg)
        st.markdown("**Login:** Password (PBKDF2-HMAC-SHA256, 100.000 iterasi + salt)"
                    + (" **+ verifikasi wajah (wajib)**" if enrolled else " — biometrik wajah belum didaftarkan"))
        st.markdown("**Teks (soal, kunci jawaban, jawaban, token, pesan):** Super-enkripsi Extended Vigenère + AES-256-GCM")
        st.markdown("**File PDF:** ChaCha20-Poly1305 + PBKDF2-SHA256 · **Gambar:** Steganografi LSB")
        st.markdown("**Aset penting:** sidik jari SHA-256 tercatat di blockchain")


def _upgrade_session_after_enroll(user):
    """Wajah baru saja diambil langsung dari kamera -> token sesi dinaikkan ke level 'face',
    supaya refresh halaman tidak meminta verifikasi wajah lagi."""
    if st.session_state.get("auth_amr") != session.AMR_FACE:
        st.session_state.auth_amr = session.AMR_FACE
        st.query_params[session.SESSION_PARAM] = session.issue_token(user, session.AMR_FACE)


def render_biometric(user, blockchain):
    st.markdown("### 🧬 Biometrik Wajah")
    state, count, detail = biometric.status(user["id"])
    with st.container(border=True):
        if state == "active":
            st.success(f"✅ Biometrik aktif — {count} foto referensi tersimpan (terenkripsi AES-256-GCM). "
                       f"Login Anda kini mewajibkan verifikasi wajah.")
        elif state == "partial":
            st.warning(f"Baru {count} dari minimal {biometric.MIN_TEMPLATES} foto referensi. "
                       f"Ambil {biometric.MIN_TEMPLATES - count} foto lagi.")
        elif state == "corrupt":
            st.error(f"⚠️ {detail} Login sementara hanya memakai password. Hapus data biometrik di bawah "
                     f"lalu daftarkan ulang wajah Anda.")
        else:
            st.warning(f"Biometrik belum didaftarkan. Ambil minimal {biometric.MIN_TEMPLATES} foto wajah "
                       f"(pencahayaan cukup, wajah menghadap kamera). Setelah aktif, login wajib verifikasi wajah.")

        if state != "corrupt":
            nonce = st.session_state.get("bio_nonce", 0)
            modes = ["Tambah foto referensi", "Uji verifikasi wajah"] if state == "active" else ["Tambah foto referensi"]
            # key ikut berubah saat status berubah, agar pilihan lama yang sudah tidak tersedia tidak tersangkut
            mode = st.radio("Aksi", modes, horizontal=True, key=f"bio_mode_{state}")
            st.caption("Tips: wajah menghadap lurus ke kamera, tanpa masker/kacamata gelap, cahaya dari depan. "
                       "Ambil foto referensi dengan sedikit variasi (jarak/cahaya) agar login lebih andal.")
            shot = st.camera_input("Ambil foto wajah", key=f"bio_cam_{nonce}")
            if shot is not None:
                face, note, annotated = biometric.detect_face(shot.getvalue())
                if annotated is not None:
                    st.image(annotated, caption=note, width=280)
                if face is None:
                    st.error(note)
                elif mode == "Tambah foto referensi":
                    if st.button("💾 Simpan sebagai foto referensi", type="primary"):
                        ok, msg = biometric.add_reference(user["id"], shot.getvalue())
                        if ok:
                            record(blockchain, "BIOMETRIC_ENROLL", "biometric", user["id"], user=user["username"])
                            if biometric.is_enrolled(user["id"]):
                                _upgrade_session_after_enroll(user)
                            st.session_state.bio_nonce = nonce + 1
                            flash(msg)
                            st.rerun()
                        st.error(msg)
                else:
                    ok, score, thr, msg = biometric.verify(user["id"], shot.getvalue())
                    (st.success if ok else st.error)(msg)
                    st.progress(max(0.0, min(1.0, score)), text=f"Skor kemiripan {score:.3f} (ambang {thr:.3f})")

        if state != "none":
            with st.expander("🗑️ Hapus data biometrik", expanded=state == "corrupt"):
                pw = st.text_input("Konfirmasi password", type="password", key="bio_del_pw",
                                   autocomplete="new-password")
                if st.button("Hapus biometrik saya"):
                    row = execute_query("SELECT password_hash FROM users WHERE id=%s", (user["id"],))
                    if row and verify_password(row["password_hash"], pw):
                        biometric.clear(user["id"])
                        session.reset_face_failures(user["id"])
                        blockchain.add_block({"event": "BIOMETRIC_DELETE", "asset": f"biometric:{user['id']}",
                                              "asset_hash": None, "user": user["username"]})
                        flash("🗑️ Data biometrik dihapus.")
                        st.rerun()
                    st.error("Password salah.")
