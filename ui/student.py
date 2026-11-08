"""Halaman Ujian Saya (mahasiswa)."""
import base64
import json

import streamlit as st

from modules.crypto_store import sha256_hex, super_encrypt
from modules.database import execute_query, get_last_error
from modules.exam_access import (
    build_enc_file, get_exam_file, integrity_note, is_pdf_exam, parse_enc_file, unlock_pdf_with_key,
    unlock_pdf_with_stego, verify_text_token,
)
from modules.integrity import record
from modules.modern_cipher import describe_file_cipher
from modules.question_bank import load_questions
from modules.stego_token import verify_stego_token
from modules.token_policy import describe_window, token_mode, window_state
from ui.common import flash, render_header, show_flash

IMAGE_TYPES = ["png", "bmp", "jpg", "jpeg", "webp"]


def hexdump(data, width=16):
    lines = []
    for i in range(0, len(data), width):
        chunk = data[i:i + width]
        hexes = " ".join(f"{b:02x}" for b in chunk).ljust(width * 3 - 1)
        text = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{i:08x}  {hexes}  |{text}|")
    return "\n".join(lines)


def _window_line(ex):
    state, msg = window_state(ex)
    icon = {"open": "🟢", "not_yet": "🟡", "expired": "🔴"}[state]
    return state, msg, f"{icon} Masa berlaku token: **{describe_window(ex)}**"


def render(current_user, blockchain):
    render_header("Portal Ujian Saya", "Daftar ujian tersedia dan status pengerjaan")
    show_flash()
    if st.session_state.get("active_exam"):
        render_active_exam(current_user, blockchain)
        return

    render_enc_opener()

    exams = execute_query("SELECT * FROM exams ORDER BY id DESC", fetch=True) or []
    subs = execute_query("SELECT * FROM student_submissions WHERE user_id = %s", (current_user["id"],), fetch=True) or []
    if not exams:
        st.info("Belum ada jadwal ujian tersedia.")
        return
    cols = st.columns(2)
    for idx, ex in enumerate(exams):
        sub = next((s for s in subs if s["exam_id"] == ex["id"]), None)
        with cols[idx % 2], st.container(border=True):
            st.markdown(f"**{ex['title']}**")
            if is_pdf_exam(ex):
                render_pdf_card(ex)
            else:
                render_pg_card(ex, sub)


# ============================================================================= .enc opener
def render_enc_opener():
    with st.expander("🔓 Buka File Ciphertext (.enc) yang Sudah Diunduh"):
        st.markdown("File `.enc` boleh diunduh kapan saja. Saat token sudah berlaku, unggah file `.enc` di sini "
                    "lalu buka dengan kunci dosen atau gambar token untuk mendapatkan PDF aslinya.")
        enc_file = st.file_uploader("File .enc", type=["enc"], key="enc_open_file")
        if not enc_file:
            return
        try:
            header, cipher_b64 = parse_enc_file(enc_file.getvalue())
        except ValueError as e:
            st.error(f"❌ {e}")
            return
        if header is None:
            st.warning("File .enc format lama (tanpa informasi ujian). Unduh ulang file .enc dari kartu ujiannya.")
            return
        exam = execute_query("SELECT * FROM exams WHERE id = %s", (header["exam_id"],))
        if not exam or exam["exam_code"] != header.get("exam_code"):
            st.error("❌ Ujian untuk file ini tidak ditemukan / sudah dihapus.")
            return
        st.markdown(f"Ujian: **{exam['exam_code']} — {exam['title']}** · Cipher: {header['cipher']} · "
                    f"KDF: {header['kdf']}")
        state, msg, line = _window_line(exam)
        st.caption(line)
        if state != "open":
            st.warning(msg)
            return
        file_rec = {"encrypted_file": cipher_b64, "file_sha256": header.get("plaintext_sha256")}
        with st.form("enc_open_form"):
            if token_mode(exam) == "stego":
                img = st.file_uploader("Gambar token steganografi dari dosen", type=IMAGE_TYPES, key="enc_open_img")
                key = None
            else:
                key = st.text_input("Kunci dosen", type="password", autocomplete="new-password", key="enc_open_key")
                img = None
            go = st.form_submit_button("🔓 Dekripsi File .enc", type="primary")
        if go:
            if token_mode(exam) == "stego":
                data, msg = (None, "⚠️ Unggah gambar token terlebih dahulu.") if not img else \
                    unlock_pdf_with_stego(exam, file_rec, img.getvalue())
            else:
                data, msg = unlock_pdf_with_key(exam, file_rec, key or "")
            if data:
                st.session_state.enc_open_plain = (exam["exam_code"], data, integrity_note(file_rec, data))
                st.success(msg)
            else:
                st.session_state.pop("enc_open_plain", None)
                st.error(msg)
        plain = st.session_state.get("enc_open_plain")
        if plain and plain[0] == exam["exam_code"]:
            if plain[2]:
                st.caption(plain[2])
            st.download_button("💾 Simpan PDF Asli", data=plain[1], file_name=f"{plain[0]}_Soal.pdf",
                               mime="application/pdf", key="enc_open_dl")


# ============================================================================= PDF card
def render_pdf_card(ex):
    st.markdown(f"<p style='font-size: 13px; color: #d97706; font-weight: 600; margin-bottom: 8px;'>📄 Tipe Ujian: "
                f"Berkas PDF (Non-PG) &nbsp;|&nbsp; Durasi: {ex['duration_minutes']} menit</p>", unsafe_allow_html=True)
    stego = token_mode(ex) == "stego"
    how = "unggah **gambar token** dari dosen" if stego else "masukkan **kunci dosen**"
    st.markdown(f"🔒 *File soal tersimpan terenkripsi ChaCha20-Poly1305 di database. Untuk membuka, {how}.*")
    state, msg, line = _window_line(ex)
    st.caption(line)

    file_rec = get_exam_file(ex["id"])
    if not file_rec:
        st.warning("⚠️ File PDF untuk ujian ini belum tersedia di database. Hubungi dosen untuk mengunggah ulang.")
        return
    plain_key = f"pdf_plain_{ex['id']}"

    # ---------- buka kunci ----------
    if state != "open":
        st.warning(msg)
    else:
        with st.form(f"pdf_unlock_{ex['id']}", clear_on_submit=False):
            if stego:
                img = st.file_uploader("Unggah gambar token steganografi (PNG asli dari dosen)", type=IMAGE_TYPES,
                                       key=f"pdf_img_{ex['id']}")
            else:
                key_in = st.text_input("Masukkan Kunci Dosen untuk Unduh PDF", type="password",
                                       key=f"pdf_key_{ex['id']}", autocomplete="new-password")
            unlock = st.form_submit_button("🔓 Buka Kunci PDF", use_container_width=True)
        if unlock:
            if stego:
                data, result = (None, "⚠️ Unggah gambar token terlebih dahulu!") if not img else \
                    unlock_pdf_with_stego(ex, file_rec, img.getvalue())
            else:
                data, result = unlock_pdf_with_key(ex, file_rec, key_in)
            if data:
                st.session_state[plain_key] = data
                st.session_state[plain_key + "_msg"] = result
            else:
                st.session_state.pop(plain_key, None)
                st.error(result)
        if st.session_state.get(plain_key):
            st.success(st.session_state.get(plain_key + "_msg", "✅ File berhasil didekripsi."))
            note = integrity_note(file_rec, st.session_state[plain_key])
            if note:
                st.caption(note)
            st.download_button("💾 Simpan PDF Asli", data=st.session_state[plain_key],
                               file_name=f"{ex['exam_code']}_Soal.pdf", mime="application/pdf",
                               key=f"save_real_{ex['id']}", use_container_width=True)

    # ---------- ciphertext ----------
    render_ciphertext_box(ex, file_rec)


def render_ciphertext_box(ex, file_rec):
    info = describe_file_cipher(file_rec["encrypted_file"])
    enc_bytes = build_enc_file(ex, file_rec)
    size_kb = f"{len(enc_bytes) / 1024:,.1f}".replace(",", "_").replace(".", ",").replace("_", ".")
    ct_size = f"{info['ukuran_ciphertext']:,}".replace(",", ".")
    st.markdown(
        f"""
<div style="border: 1px dashed #1a7f5a; background: #f0fdf4; border-radius: 10px; padding: 12px 14px; margin: 10px 0 8px 0;">
  <div style="font-weight: 700; color: #14532d; margin-bottom: 4px;">📦 Soal tersedia dalam bentuk TERENKRIPSI (ciphertext)</div>
  <div style="font-size: 13px; color: #166534; line-height: 1.5;">
    File <code>.enc</code> berisi soal PDF ujian ini yang sudah dienkripsi <b>{info['algoritma']}</b>.
    Soal ini <b>bisa dilihat dan diunduh kapan saja</b> — bahkan sebelum token berlaku — namun isinya
    berupa <b>enkripsi dari PDF tersebut</b>, sehingga tidak dapat dibaca tanpa
    {'gambar token' if token_mode(ex) == 'stego' else 'kunci dosen'} yang sah.
    Setelah token berlaku, buka file ini melalui menu <b>🔓 Buka File Ciphertext (.enc)</b> di atas.
  </div>
  <div style="font-size: 12px; color: #15803d; margin-top: 6px;">
    Ukuran: {size_kb} KB · KDF: {info['kdf']} · Integritas: Poly1305 tag
  </div>
</div>
""",
        unsafe_allow_html=True,
    )
    with st.expander("👁️ Lihat isi ciphertext"):
        st.markdown(
            f"| Komponen | Nilai |\n|---|---|\n"
            f"| Algoritma | {info['algoritma']} |\n"
            f"| Penurunan kunci | {info['kdf']} |\n"
            f"| Salt | `{info['salt']}` |\n"
            f"| Nonce (96-bit) | `{info['nonce']}` |\n"
            f"| Tag autentikasi Poly1305 | `{info['tag']}` |\n"
            f"| Ukuran ciphertext | {ct_size} byte |\n"
            f"| SHA-256 ciphertext | `{sha256_hex(base64.b64decode(file_rec['encrypted_file']))}` |"
        )
        st.caption("Cuplikan 96 byte pertama ciphertext (hex dump) — terlihat acak, tidak ada struktur PDF (%PDF):")
        st.code(hexdump(info["preview"]), language="text")
    st.download_button("🔒 Download File Ciphertext (.enc)", data=enc_bytes,
                       file_name=f"{ex['exam_code']}_encrypted.enc", mime="application/octet-stream",
                       key=f"save_cipher_{ex['id']}", use_container_width=True)


# ============================================================================= PG card
def render_pg_card(ex, sub):
    st.markdown(f"<p style='font-size: 13px; color: #64748b; margin-bottom: 8px;'>Kode: <code>{ex['exam_code']}</code>"
                f" &nbsp;|&nbsp; Durasi: {ex['duration_minutes']} menit</p>", unsafe_allow_html=True)
    if sub:
        st.markdown(f"""<div style='background-color: #dcfce7; border: 1px solid #bbf7d0; padding: 6px 10px; border-radius: 6px;
            font-size: 13px; color: #166534; font-weight: 600; margin-bottom: 10px;'>✅ Selesai (Nilai: {sub['score']})</div>""",
                    unsafe_allow_html=True)
        st.button("Sudah Dikerjakan", key=f"done_{ex['id']}", disabled=True, use_container_width=True)
        return
    st.markdown("""<div style='background-color: #fef9c3; border: 1px solid #fef08a; padding: 6px 10px; border-radius: 6px;
        font-size: 13px; color: #854d0e; font-weight: 600; margin-bottom: 10px;'>⚠️ Belum Dikerjakan</div>""",
                unsafe_allow_html=True)
    stego = token_mode(ex) == "stego"
    state, msg, line = _window_line(ex)
    st.caption(line + (" · 🖼️ Token berupa gambar steganografi" if stego else " · 🔤 Token teks"))

    if st.session_state.get("token_target_exam_id") != ex["id"]:
        if st.button("Mulai Ujian PG →", key=f"start_{ex['id']}", use_container_width=True, disabled=state != "open"):
            st.session_state.token_target_exam_id = ex["id"]
            st.rerun()
        if state != "open":
            st.caption(msg)
        return

    st.markdown("---")
    if stego:
        img = st.file_uploader("Unggah gambar token dari dosen (PNG asli)", type=IMAGE_TYPES, key=f"tokimg_{ex['id']}")
    else:
        tok = st.text_input("Token Dosen", key=f"tok_{ex['id']}", placeholder="Masukkan token...")
    bx1, bx2 = st.columns(2)
    if bx1.button("Submit", key=f"verify_{ex['id']}", type="primary", use_container_width=True):
        if stego:
            ok, result = (False, "⚠️ Unggah gambar token terlebih dahulu!") if not img else \
                verify_stego_token(ex, img.getvalue())[:2]
        else:
            ok, result = verify_text_token(ex, tok)
        if not ok:
            st.error(result)
        else:
            try:
                questions = load_questions(ex["id"], ex["encrypted_question"])
                if not questions:
                    raise ValueError("Ujian ini belum memiliki soal.")
                st.session_state.active_exam = {
                    "exam_info": ex, "questions": questions,
                    "answer_key": {str(i): q["correct"] for i, q in enumerate(questions)},
                }
                st.session_state.current_question_idx = 0
                st.session_state.student_answers = {}
                st.session_state.token_target_exam_id = None
                flash(f"{result} Soal dimuat — selamat mengerjakan!")
                st.rerun()
            except Exception as e:
                st.error(f"Error dekripsi: {e}")
    if bx2.button("Batal", key=f"cancel_{ex['id']}", use_container_width=True):
        st.session_state.token_target_exam_id = None
        st.rerun()


# ============================================================================= exam in progress
def render_active_exam(current_user, blockchain):
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
                if st.button(str(i + 1), key=f"nav_{i}", use_container_width=True):
                    st.session_state.current_question_idx = i
                    st.rerun()
        st.markdown("---")
        if st.button("🏳️ Keluar Ujian"):
            st.session_state.active_exam = None
            st.rerun()

    with col_content:
        q_data = questions[q_idx]
        st.markdown(f"### Soal {q_idx + 1} dari {len(questions)}")
        with st.container(border=True):
            st.markdown(f"**{q_data['question']}**")
        current_ans = st.session_state.student_answers.get(q_idx, None)
        opts = ["A", "B", "C", "D"]
        default_idx = opts.index(current_ans) if current_ans in opts else 0
        selected = st.radio("Pilih jawaban:", opts, format_func=lambda x: f"{x}. {q_data['options'][x]}",
                            index=default_idx, key=f"radio_{q_idx}")
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
            score = round((correct / len(questions)) * 100, 2)
            # Jawaban disimpan dengan SUPER ENKRIPSI (Vigenère + AES-256-GCM)
            enc_ans = super_encrypt(json.dumps({str(k): v for k, v in st.session_state.student_answers.items()}),
                                    "answers")
            sub_id = execute_query("""
                INSERT INTO student_submissions (user_id, exam_id, encrypted_answers, score, status)
                VALUES (%s, %s, %s, %s, 'Finished')
            """, (current_user["id"], ex_info["id"], enc_ans, score), return_id=True)
            if not sub_id:
                st.error(f"Gagal menyimpan jawaban: {get_last_error()}")
                return
            # Nilai = aset penting -> sidik jarinya dikunci di blockchain
            record(blockchain, "SUBMIT_EXAM", "submission", sub_id, student=current_user["username"],
                   exam_code=ex_info["exam_code"], score=score)
            st.session_state.active_exam = None
            flash(f"🎉 Ujian selesai! Nilai Anda: **{score:.1f}** (tercatat di blockchain).", balloons=True)
            st.rerun()
