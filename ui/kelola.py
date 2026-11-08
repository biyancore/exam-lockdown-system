"""Halaman Kelola Ujian (dosen)."""
import io
import os
from datetime import datetime

import streamlit as st

from modules.database import execute_query, get_last_error
from modules.exam_access import (
    get_exam_file, get_pdf_key, is_pdf_exam, save_exam_file, decrypt_with_key,
    text_token_columns, text_token_plain, update_validity,
)
from modules.integrity import record
from modules.question_bank import (
    OPTION_KEYS, count_questions, load_questions, normalize_question, save_questions, save_single_question,
)
from modules.stego_token import (
    active_token_count, create_stego_token, delete_token, inspect_image, list_tokens,
    revoke_all_for_exam, set_active, token_images,
)
from modules.token_policy import TOKEN_MODE_LABEL, describe_window, fmt_dt, status_badge, token_mode, window_state
from ui.common import flash, image_compare, render_header, show_flash, tab_css, validate_window, validity_editor

TAB_PG = "➕ Buat & Edit Ujian PG"
TAB_LIST = "📂 Daftar & Kelola Ujian"
TAB_PDF = "📄 Unggah Ujian PDF"
TAB_STEGO = "🖼️ Token Steganografi"
KELOLA_TABS = [TAB_PG, TAB_LIST, TAB_PDF, TAB_STEGO]

BUILTIN_COVERS = {
    "Latar ujian (default_exam_bg.jpg)": os.path.join("assets", "default_exam_bg.jpg"),
    "Logo UPN (logo_upnvy.png)": os.path.join("assets", "logo_upnvy.png"),
    "Gambar token lama (stego_exam_token.png)": os.path.join("assets", "stego_exam_token.png"),
}


# ----------------------------------------------------------------------------- callbacks
def _bump_nonce():
    st.session_state.pg_form_nonce = st.session_state.get("pg_form_nonce", 0) + 1


def start_edit_pg(exam_id):
    st.session_state.editing_exam_id = exam_id
    _bump_nonce()
    st.session_state.kelola_tab = TAB_PG


def start_new_pg():
    st.session_state.editing_exam_id = None
    _bump_nonce()
    st.session_state.kelola_tab = TAB_PG


def go_to_exam_list():
    st.session_state.editing_exam_id = None
    _bump_nonce()
    st.session_state.kelola_tab = TAB_LIST


def open_stego_for(exam_id):
    st.session_state.stego_exam_id = exam_id
    st.session_state.kelola_tab = TAB_STEGO


def _exam_label(ex):
    kind = "PDF" if is_pdf_exam(ex) else "PG"
    return f"[{kind}] {ex['exam_code']} — {ex['title']}"


# ============================================================================= PAGE
def render(current_user, blockchain):
    render_header("Kelola Ujian", "Buat dan kelola bank soal, token ujian, dan token gambar steganografi")
    st.markdown(tab_css("kelola_tab"), unsafe_allow_html=True)

    pending_tab = st.session_state.pop("pending_kelola_tab", None)
    if pending_tab in KELOLA_TABS:
        st.session_state.kelola_tab = pending_tab
    if st.session_state.get("kelola_tab") not in KELOLA_TABS:
        st.session_state.kelola_tab = TAB_PG

    active_tab = st.radio("Navigasi Kelola Ujian", KELOLA_TABS, key="kelola_tab",
                          horizontal=True, label_visibility="collapsed")
    show_flash()

    if active_tab == TAB_PG:
        render_pg_editor(current_user, blockchain)
    elif active_tab == TAB_LIST:
        render_exam_list(current_user, blockchain)
    elif active_tab == TAB_PDF:
        render_pdf_upload(current_user, blockchain)
    else:
        render_stego_tab(current_user, blockchain)


# ============================================================================= TAB 1: PG
def render_pg_editor(current_user, blockchain):
    exam_id = st.session_state.get("editing_exam_id")
    nonce = st.session_state.get("pg_form_nonce", 0)
    exam_row = None
    if exam_id:
        exam_row = execute_query("SELECT * FROM exams WHERE id = %s", (exam_id,))
        if not exam_row or is_pdf_exam(exam_row):
            st.session_state.editing_exam_id = None
            exam_id, exam_row = None, None

    old_questions = []
    if exam_row:
        try:
            old_questions = load_questions(exam_id, exam_row["encrypted_question"])
        except Exception as e:
            st.error(f"Gagal mendekripsi soal lama: {e}")
        meta = {
            "code": exam_row["exam_code"], "title": exam_row["title"],
            "duration": int(exam_row["duration_minutes"] or 90),
            "token": text_token_plain(exam_row) or "", "mode": token_mode(exam_row),
        }
    else:
        meta = {"code": "", "title": "Ujian Akhir Semester", "duration": 90, "token": "TOKEN-UPN-99", "mode": "text"}

    pf = f"pg_{exam_id or 'new'}_{nonce}"
    st.session_state.setdefault(f"{pf}_code", meta["code"])
    st.session_state.setdefault(f"{pf}_title", meta["title"])
    st.session_state.setdefault(f"{pf}_dur", meta["duration"])
    st.session_state.setdefault(f"{pf}_token", meta["token"])
    st.session_state.setdefault(f"{pf}_tmode", meta["mode"])
    st.session_state.setdefault(f"{pf}_count", max(1, len(old_questions)))

    if exam_row:
        st.info(
            f"✏️ **Mode Edit Ujian PG: {exam_row['title']}** — {len(old_questions)} soal lama dimuat dari "
            f"database (tabel `exam_questions`). Ubah soal yang perlu lalu simpan; soal lain tetap aman."
        )
        nb1, nb2, _ = st.columns([1, 1, 2])
        nb1.button("⬅️ Kembali ke Daftar", on_click=go_to_exam_list, use_container_width=True)
        nb2.button("➕ Buat Ujian Baru", on_click=start_new_pg, use_container_width=True)

    st.markdown("### 📋 Informasi Dasar Ujian PG")
    c1, c2 = st.columns(2)
    with c1:
        code = st.text_input("Kode Ujian", key=f"{pf}_code", placeholder="contoh: KRIPTO-2026-A")
        title = st.text_input("Judul Ujian", key=f"{pf}_title")
    with c2:
        dur = st.number_input("Durasi (menit)", min_value=1, step=1, key=f"{pf}_dur")

    # ---------------- Token ----------------
    st.markdown("### 🔑 Token Ujian")
    mode = st.radio("Jenis token", list(TOKEN_MODE_LABEL), key=f"{pf}_tmode", horizontal=True,
                    format_func=lambda m: TOKEN_MODE_LABEL[m])
    token = st.session_state.get(f"{pf}_token", "")
    if mode == "text":
        token = st.text_input("Token Rahasia Ujian", key=f"{pf}_token",
                              help="Disimpan sebagai hash PBKDF2-SHA256 + salinan super-enkripsi (Vigenère + AES).")
    else:
        n_img = active_token_count(exam_id) if exam_id else 0
        if exam_id and n_img:
            st.success(f"🖼️ Mahasiswa wajib mengunggah gambar token. Gambar token aktif: **{n_img}**.")
        else:
            st.warning("🖼️ Mahasiswa wajib mengunggah gambar token. Setelah menyimpan ujian, buat gambarnya di tab "
                       "**🖼️ Token Steganografi** (belum ada gambar aktif → ujian belum bisa dibuka).")
        if exam_id:
            st.button("➡️ Buka tab Token Steganografi untuk ujian ini", on_click=open_stego_for, args=(exam_id,))
    use_v, v_start, v_end = validity_editor(
        f"{pf}_val", exam_row.get("token_valid_from") if exam_row else None,
        exam_row.get("token_valid_until") if exam_row else None,
    )

    # ---------------- Soal ----------------
    num_q = int(st.number_input("Jumlah Soal", min_value=1, max_value=50, step=1, key=f"{pf}_count"))
    if exam_row and num_q < len(old_questions):
        st.warning(
            f"⚠️ Jumlah soal dikurangi: soal nomor {num_q + 1}–{len(old_questions)} akan dihapus dari "
            f"database saat Anda menekan **Simpan Semua**. Kembalikan jumlahnya untuk membatalkan."
        )

    st.markdown("### ✍️ Bank Soal Pilihan Ganda")
    questions_data = []
    for i in range(num_q):
        q_old = normalize_question(old_questions[i] if i < len(old_questions) else {})
        k = f"{pf}_{i}"
        st.session_state.setdefault(f"{k}_q", q_old["question"])
        for opt in OPTION_KEYS:
            st.session_state.setdefault(f"{k}_{opt}", q_old["options"][opt])
        st.session_state.setdefault(f"{k}_ans", q_old["correct"])

        in_db = exam_row is not None and i < len(old_questions)
        label = f"Soal {i + 1}"
        if exam_row:
            label += "  ·  💾 tersimpan" if in_db else "  ·  🆕 baru"

        with st.expander(label, expanded=(i == 0)):
            q_text = st.text_area("Pertanyaan", key=f"{k}_q", height=80)
            cols = st.columns(4)
            opts = {opt: cols[j].text_input(opt, key=f"{k}_{opt}") for j, opt in enumerate(OPTION_KEYS)}
            correct = st.selectbox("Kunci Jawaban", OPTION_KEYS, key=f"{k}_ans")

            if in_db:
                if st.button(f"💾 Simpan Soal {i + 1} Saja", key=f"{k}_save"):
                    if not q_text.strip() or not all(v.strip() for v in opts.values()):
                        st.error("Pertanyaan dan semua opsi A–D wajib diisi.")
                    elif save_single_question(exam_id, i + 1, {"question": q_text, "options": opts, "correct": correct}):
                        record(blockchain, "EDIT_QUESTION", "exam", exam_id,
                               question_no=i + 1, editor=current_user["username"])
                        flash(f"✅ Soal {i + 1} berhasil disimpan ke database.")
                        st.rerun()
                    else:
                        st.error(f"Gagal menyimpan soal: {get_last_error()}")
            elif exam_row:
                st.caption("Soal baru — tersimpan setelah Anda menekan **Simpan Semua Perubahan**.")

        questions_data.append({"question": q_text, "options": opts, "correct": correct})

    btn_label = "💾 Simpan Semua Perubahan & Enkripsi Ulang" if exam_row else "🚀 Terbitkan Ujian PG"
    if not st.button(btn_label, type="primary", key=f"{pf}_submit"):
        return

    code, title, token = code.strip(), title.strip(), (token or "").strip()
    empty_q = [i + 1 for i, q in enumerate(questions_data) if not q["question"].strip()]
    empty_opt = [i + 1 for i, q in enumerate(questions_data)
                 if q["question"].strip() and not all(v.strip() for v in q["options"].values())]
    duplicate = execute_query("SELECT id FROM exams WHERE exam_code = %s AND id <> %s",
                              (code, exam_id or 0)) if code else None
    v_err, v_from, v_until = validate_window(use_v, v_start, v_end)

    if not code or not title:
        st.error("Kode ujian dan judul wajib diisi!")
    elif mode == "text" and not token:
        st.error("Token teks wajib diisi (atau pilih token gambar steganografi).")
    elif duplicate:
        st.error(f"Kode ujian `{code}` sudah dipakai ujian lain. Gunakan kode yang berbeda.")
    elif v_err:
        st.error(v_err)
    elif empty_q:
        st.error(f"Pertanyaan soal nomor {empty_q} masih kosong!")
    elif empty_opt:
        st.error(f"Opsi jawaban soal nomor {empty_opt} belum lengkap (A–D wajib diisi)!")
    else:
        if token:
            token_hash, token_enc = text_token_columns(token)
        elif exam_row:  # mode stego: token teks lama dibiarkan apa adanya
            token_hash, token_enc = exam_row["token_hash"], exam_row.get("token_encrypted")
        else:  # mode stego pada ujian baru: token teks acak (tidak dipakai)
            token_hash, token_enc = text_token_columns(os.urandom(16).hex())
        if exam_row:
            ok = execute_query(
                """UPDATE exams SET exam_code=%s, title=%s, duration_minutes=%s, token_hash=%s, token_encrypted=%s,
                   token_mode=%s, token_valid_from=%s, token_valid_until=%s WHERE id=%s""",
                (code, title, int(dur), token_hash, token_enc, mode, v_from, v_until, exam_id),
            ) is not None and save_questions(exam_id, questions_data)
            if not ok:
                st.error(f"Gagal menyimpan perubahan: {get_last_error()}")
                return
            record(blockchain, "EDIT_EXAM", "exam", exam_id, exam_code=code,
                   total_questions=len(questions_data), token_mode=mode, editor=current_user["username"])
            st.session_state.pg_form_nonce = nonce + 1
            flash(f"✅ Ujian PG '{title}' berhasil diperbarui — {len(questions_data)} soal tersimpan di database.",
                  balloons=True)
            st.rerun()
        else:
            new_id = execute_query(
                """INSERT INTO exams (exam_code, title, encrypted_question, encrypted_answer_key, duration_minutes,
                   token_hash, token_encrypted, token_mode, token_valid_from, token_valid_until)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
                (code, title, "", "", int(dur), token_hash, token_enc, mode, v_from, v_until), return_id=True,
            )
            if not new_id:
                st.error(f"Gagal membuat ujian: {get_last_error()}")
                return
            if not save_questions(new_id, questions_data):
                err = get_last_error()
                execute_query("DELETE FROM exams WHERE id = %s", (new_id,))
                st.error(f"Gagal menyimpan soal ke database: {err}")
                return
            record(blockchain, "CREATE_EXAM", "exam", new_id, exam_code=code,
                   total_questions=len(questions_data), token_mode=mode, creator=current_user["username"])
            st.session_state.pg_form_nonce = nonce + 1
            msg = (f"🎉 Ujian PG '{title}' selesai dibuat! {len(questions_data)} soal terenkripsi tersimpan di database. "
                   f"Untuk mengubahnya, buka tab **Daftar & Kelola Ujian** lalu klik **✏️ Edit PG**.")
            if mode == "stego":
                msg += " Jangan lupa buat gambar token di tab **🖼️ Token Steganografi**."
                st.session_state.stego_exam_id = new_id
            flash(msg, balloons=True)
            st.rerun()


# ============================================================================= TAB 2: LIST
def _token_caption(ex):
    mode = token_mode(ex)
    if mode == "stego":
        token_txt = f"🖼️ Gambar stego ({active_token_count(ex['id'])} aktif)"
    elif is_pdf_exam(ex):
        token_txt = "🔤 Kunci PDF (teks)"
    else:
        token_txt = f"🔤 Token: `{text_token_plain(ex) or '-'}`"
    return f"{token_txt} · {status_badge(ex)}"


def render_exam_list(current_user, blockchain):
    st.markdown("### 📂 Daftar Seluruh Ujian Terbit")
    exams = execute_query("SELECT * FROM exams ORDER BY id DESC", fetch=True) or []
    if not exams:
        st.info("Belum ada ujian yang diterbitkan.")
        return
    pg_exams = [e for e in exams if not is_pdf_exam(e)]
    pdf_exams = [e for e in exams if is_pdf_exam(e)]

    st.markdown("#### 📝 Ujian Pilihan Ganda (PG)")
    if not pg_exams:
        st.caption("Belum ada ujian pilihan ganda.")
    cols_pg = st.columns(2)
    for idx, ex in enumerate(pg_exams):
        with cols_pg[idx % 2], st.container(border=True):
            st.markdown(f"**{ex['title']}**")
            st.caption(f"Kode: `{ex['exam_code']}` · Durasi: {ex['duration_minutes']} mnt · "
                       f"Jumlah soal: {count_questions(ex['id'])}")
            st.caption(_token_caption(ex))
            c1, c2, c3 = st.columns(3)
            c1.button("✏️ Edit PG", key=f"edit_pg_{ex['id']}", use_container_width=True,
                      on_click=start_edit_pg, args=(ex["id"],))
            c2.button("🖼️ Token Gambar", key=f"stego_pg_{ex['id']}", use_container_width=True,
                      on_click=open_stego_for, args=(ex["id"],))
            if c3.button("🗑️ Hapus", key=f"del_pg_{ex['id']}", use_container_width=True):
                execute_query("DELETE FROM exams WHERE id = %s", (ex["id"],))
                if st.session_state.get("editing_exam_id") == ex["id"]:
                    st.session_state.editing_exam_id = None
                blockchain.add_block({"event": "DELETE_EXAM", "exam_id": ex["id"], "asset": f"exam:{ex['id']}",
                                      "asset_hash": None, "user": current_user["username"]})
                flash("🗑️ Ujian PG dihapus!")
                st.rerun()

    st.markdown("---")
    st.markdown("#### 📄 Ujian Berkas PDF (ChaCha20-Poly1305)")
    if not pdf_exams:
        st.caption("Belum ada ujian PDF yang diunggah.")
    cols_pdf = st.columns(2)
    for idx, ex in enumerate(pdf_exams):
        with cols_pdf[idx % 2], st.container(border=True):
            st.markdown(f"**{ex['title']}**")
            st.caption(f"Kode: `{ex['exam_code']}` · Durasi: {ex['duration_minutes']} mnt · Tipe: PDF File")
            file_rec = get_exam_file(ex["id"])
            if file_rec:
                size = f" · {file_rec['file_size'] / 1024:.0f} KB" if file_rec.get("file_size") else ""
                st.caption(f"Status File: ✅ Terenkripsi di Database{size}")
            else:
                st.caption("Status File: ⚠️ File Kosong — unggah ulang lewat ✏️ Edit PDF")
            st.caption(_token_caption(ex))
            c1, c2, c3 = st.columns(3)
            if c1.button("✏️ Edit PDF", key=f"edit_pdf_{ex['id']}", use_container_width=True):
                st.session_state.editing_pdf_id = ex["id"]
                st.rerun()
            c2.button("🖼️ Token Gambar", key=f"stego_pdf_{ex['id']}", use_container_width=True,
                      on_click=open_stego_for, args=(ex["id"],))
            if c3.button("🗑️ Hapus PDF", key=f"del_pdf_{ex['id']}", use_container_width=True):
                execute_query("DELETE FROM exams WHERE id = %s", (ex["id"],))
                blockchain.add_block({"event": "DELETE_PDF_EXAM", "exam_id": ex["id"], "asset": f"exam_file:{ex['id']}",
                                      "asset_hash": None, "user": current_user["username"]})
                flash("🗑️ Ujian PDF berhasil dihapus!")
                st.rerun()

    if st.session_state.get("editing_pdf_id"):
        render_pdf_edit(current_user, blockchain)


def render_pdf_edit(current_user, blockchain):
    data = execute_query("SELECT * FROM exams WHERE id = %s", (st.session_state.editing_pdf_id,))
    if not data:
        st.session_state.editing_pdf_id = None
        return
    old_file_rec = get_exam_file(data["id"])
    st.markdown("---")
    st.warning(f"✏️ Edit Ujian Berkas PDF: **{data['title']}**")
    pfx = f"pdfedit_{data['id']}"
    with st.form("form_edit_pdf_complete"):
        ne_code = st.text_input("Kode Ujian", value=data["exam_code"])
        ne_title = st.text_input("Judul Ujian", value=data["title"])
        ne_dur = st.number_input("Durasi (menit)", value=int(data["duration_minutes"]), min_value=1)
        ne_mode = st.radio("Cara mahasiswa membuka PDF", list(TOKEN_MODE_LABEL), horizontal=True,
                           index=list(TOKEN_MODE_LABEL).index(token_mode(data)),
                           format_func=lambda m: {"text": "🔤 Ketik kunci dosen",
                                                  "stego": "🖼️ Unggah gambar token steganografi"}[m])
        ne_key = st.text_input("Kunci Enkripsi Baru (kosongkan jika tidak diubah)", type="password",
                               autocomplete="new-password")
        ne_key2 = st.text_input("Ulangi Kunci Enkripsi Baru", type="password", autocomplete="new-password")
        st.caption("⚠️ Mengganti kunci otomatis mencabut semua gambar token lama ujian ini (kuncinya tersimpan di gambar).")
        ne_uploaded_pdf = st.file_uploader("Unggah File PDF Baru (Opsional)", type=["pdf"])
        st.markdown("**Masa berlaku token / kunci**")
        use_v, v_start, v_end = validity_editor(pfx, data.get("token_valid_from"), data.get("token_valid_until"),
                                                in_form=True)
        b_save, b_cancel = st.columns(2)
        save_pdf = b_save.form_submit_button("💾 Simpan Perubahan PDF", type="primary", use_container_width=True)
        cancel_pdf = b_cancel.form_submit_button("❌ Batal", use_container_width=True)

    if cancel_pdf:
        st.session_state.editing_pdf_id = None
        st.rerun()
    if not save_pdf:
        return

    new_key = ne_key.strip()
    v_err, v_from, v_until = validate_window(use_v, v_start, v_end)
    if new_key != ne_key2.strip():
        st.error("Kunci baru dan ulangi kunci tidak sama!")
        return
    if v_err:
        st.error(v_err)
        return
    if ne_uploaded_pdf is None and old_file_rec is None:
        st.error("Ujian ini belum punya file PDF. Unggah file PDF baru terlebih dahulu.")
        return
    old_key = get_pdf_key(old_file_rec) if old_file_rec else None
    if ne_uploaded_pdf is not None and not new_key and not old_key:
        st.error("Isi kunci enkripsi untuk file PDF baru.")
        return

    ok = execute_query(
        "UPDATE exams SET exam_code=%s, title=%s, duration_minutes=%s, token_mode=%s, token_valid_from=%s, "
        "token_valid_until=%s WHERE id=%s",
        (ne_code.strip(), ne_title.strip(), int(ne_dur), ne_mode, v_from, v_until, data["id"]),
    ) is not None
    file_changed = False
    if ok and ne_uploaded_pdf is not None:
        ok = save_exam_file(data["id"], ne_uploaded_pdf.getvalue(), new_key or old_key, ne_uploaded_pdf.name)
        file_changed = True
    elif ok and new_key:
        dec_old = decrypt_with_key(old_file_rec, old_key)
        if dec_old is None:
            st.error("File lama gagal didekripsi dengan kunci tersimpan. Unggah ulang file PDF beserta kunci baru.")
            return
        ok = save_exam_file(data["id"], dec_old, new_key, old_file_rec.get("file_name"))
        file_changed = True

    if not ok:
        st.error(f"Gagal menyimpan: {get_last_error()}")
        return
    revoked = 0
    if new_key and new_key != old_key:
        revoked = revoke_all_for_exam(data["id"]) or 0
    record(blockchain, "EDIT_PDF_EXAM", "exam", data["id"], editor=current_user["username"])
    if file_changed:
        record(blockchain, "UPDATE_PDF_FILE", "exam_file", data["id"], editor=current_user["username"])
    st.session_state.editing_pdf_id = None
    msg = "✅ Ujian Berkas PDF berhasil diperbarui!"
    if revoked:
        msg += f" {revoked} gambar token lama dicabut karena kunci berubah — buat gambar token baru."
    flash(msg)
    st.rerun()


# ============================================================================= TAB 3: PDF
def render_pdf_upload(current_user, blockchain):
    st.markdown("### 📄 Unggah Ujian Berkas PDF")
    st.markdown("File PDF dienkripsi dengan **ChaCha20-Poly1305** (kunci diturunkan dengan PBKDF2-SHA256 + salt) — "
                "algoritma berbeda dari enkripsi teks (Vigenère + AES-256-GCM).")
    with st.form("pdf_exam_form"):
        p_code = st.text_input("Kode Ujian PDF", placeholder="contoh: PDF-KRIPTO-2026")
        p_title = st.text_input("Judul Ujian PDF", value="Ujian Praktikum Kriptografi")
        p_duration = st.number_input("Durasi (menit)", value=60, min_value=1)
        p_key = st.text_input("Kunci Enkripsi File PDF (Kunci Rahasia)", type="password", autocomplete="new-password")
        p_key2 = st.text_input("Ulangi Kunci Enkripsi", type="password", autocomplete="new-password")
        p_mode = st.radio("Cara mahasiswa membuka PDF", list(TOKEN_MODE_LABEL), horizontal=True,
                          format_func=lambda m: {"text": "🔤 Ketik kunci dosen",
                                                 "stego": "🖼️ Unggah gambar token steganografi"}[m])
        uploaded_pdf = st.file_uploader("Pilih File Soal (Format PDF)", type=["pdf"])
        st.markdown("**Masa berlaku token / kunci**")
        use_v, v_start, v_end = validity_editor("pdfnew", in_form=True)
        submit_pdf = st.form_submit_button("🚀 Enkripsi & Terbitkan Ujian PDF", type="primary")

    if not submit_pdf:
        return
    key_clean, code = p_key.strip(), p_code.strip()
    duplicate = execute_query("SELECT id FROM exams WHERE exam_code = %s", (code,)) if code else None
    v_err, v_from, v_until = validate_window(use_v, v_start, v_end)
    if not code or not p_title.strip():
        st.error("Kode dan judul ujian wajib diisi!")
    elif duplicate:
        st.error(f"Kode ujian `{code}` sudah dipakai. Gunakan kode lain.")
    elif not uploaded_pdf:
        st.error("Silakan unggah file PDF terlebih dahulu!")
    elif not key_clean:
        st.error("Kunci enkripsi file wajib diisi!")
    elif key_clean != p_key2.strip():
        st.error("Kunci dan ulangi kunci tidak sama!")
    elif v_err:
        st.error(v_err)
    else:
        new_id = execute_query(
            """INSERT INTO exams (exam_code, title, encrypted_question, encrypted_answer_key, duration_minutes,
               token_hash, token_mode, token_valid_from, token_valid_until)
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)""",
            (code, p_title.strip(), "[FILE_PDF_ENCRYPTED]", "PDF_MODE_KEY", int(p_duration), "PDF_MODE",
             p_mode, v_from, v_until), return_id=True,
        )
        if not new_id:
            st.error(f"Gagal membuat ujian: {get_last_error()}")
        elif not save_exam_file(new_id, uploaded_pdf.getvalue(), key_clean, uploaded_pdf.name):
            err = get_last_error()
            execute_query("DELETE FROM exams WHERE id = %s", (new_id,))
            st.error(f"Gagal menyimpan file PDF ke database: {err}")
        else:
            record(blockchain, "CREATE_PDF_EXAM", "exam", new_id, exam_code=code, creator=current_user["username"])
            record(blockchain, "UPLOAD_PDF_FILE", "exam_file", new_id, exam_code=code)
            msg = f"🎉 Ujian PDF '{p_title.strip()}' berhasil dienkripsi dan disimpan ke database!"
            if p_mode == "stego":
                msg += " Buat gambar tokennya di tab **🖼️ Token Steganografi**."
                st.session_state.stego_exam_id = new_id
            flash(msg, balloons=True)
            st.rerun()


# ============================================================================= TAB 4: STEGO
def render_stego_tab(current_user, blockchain):
    st.markdown("### 🖼️ Token Ujian Berbentuk Gambar Steganografi")
    st.markdown(
        "Token rahasia dienkripsi (**Extended Vigenère + AES-256-GCM**) lalu disembunyikan di bit terakhir (LSB) "
        "piksel gambar. Gambar terlihat sama persis dengan aslinya, tetapi **hanya gambar token** yang bisa membuka "
        "soal. Gambar asli, screenshot, atau gambar yang dikompres (JPG/WhatsApp) akan ditolak."
    )
    with st.expander("ℹ️ Cara kerja & alur pemakaian"):
        st.markdown(
            "1. Pilih ujian, lalu pilih gambar sampul (unggah sendiri atau gambar bawaan).\n"
            "2. Aplikasi membuat **rahasia acak 128-bit + ID token**. Untuk ujian PDF, **kunci PDF ikut disisipkan** "
            "sehingga gambar itu sendiri yang membuka file.\n"
            "3. Payload disuper-enkripsi lalu disisipkan ke LSB → gambar token (PNG).\n"
            "4. Database hanya menyimpan **SHA-256 rahasia**, hash gambar, dan gambar dalam bentuk **terenkripsi AES**. "
            "Pembuatan / pencabutan token dicatat di **blockchain**.\n"
            "5. Unduh gambar token dan bagikan ke mahasiswa **sebagai file/dokumen** (jangan sebagai foto, karena "
            "akan dikompres).\n"
            "6. Mahasiswa mengunggah gambar token saat membuka ujian. Token dicek: milik ujian ini, belum dicabut, "
            "dan masih dalam **masa berlaku**."
        )

    exams = execute_query("SELECT * FROM exams ORDER BY id DESC", fetch=True) or []
    if not exams:
        st.info("Belum ada ujian. Buat ujian PG atau PDF terlebih dahulu.")
        return
    ids = [e["id"] for e in exams]
    if st.session_state.get("stego_exam_id") not in ids:
        st.session_state.stego_exam_id = ids[0]
    exam_id = st.selectbox("Pilih ujian", ids, key="stego_exam_id",
                           format_func=lambda i: _exam_label(next(e for e in exams if e["id"] == i)))
    exam = next(e for e in exams if e["id"] == exam_id)
    pdf_mode = is_pdf_exam(exam)

    # ---------------- Pengaturan token ujian ----------------
    with st.container(border=True):
        st.markdown(f"**⚙️ Pengaturan token: {exam['title']}**")
        st.caption(f"Jenis token saat ini: {TOKEN_MODE_LABEL[token_mode(exam)]} · {status_badge(exam)}")
        sp = f"stg_{exam_id}_{st.session_state.get('stego_settings_nonce', 0)}"
        st.session_state.setdefault(f"{sp}_req", token_mode(exam) == "stego")
        require = st.toggle("Wajibkan gambar token steganografi untuk membuka ujian ini", key=f"{sp}_req")
        use_v, v_start, v_end = validity_editor(sp, exam.get("token_valid_from"), exam.get("token_valid_until"))
        if st.button("💾 Simpan pengaturan token", key=f"{sp}_save"):
            v_err, v_from, v_until = validate_window(use_v, v_start, v_end)
            if v_err:
                st.error(v_err)
            else:
                execute_query("UPDATE exams SET token_mode=%s WHERE id=%s", ("stego" if require else "text", exam_id))
                update_validity(exam_id, v_from, v_until)
                record(blockchain, "UPDATE_TOKEN_SETTINGS", "exam", exam_id,
                       token_mode="stego" if require else "text", editor=current_user["username"])
                st.session_state.stego_settings_nonce = st.session_state.get("stego_settings_nonce", 0) + 1
                flash("✅ Pengaturan token disimpan.")
                st.rerun()
        if require and active_token_count(exam_id) == 0:
            st.warning("Belum ada gambar token aktif — mahasiswa belum bisa membuka ujian ini. Buat di bawah.")

    sub_create, sub_list, sub_verify = st.tabs(["🧬 Buat Gambar Token", "🗂️ Daftar Gambar Token", "🔍 Uji Gambar"])

    # ---------------- Buat ----------------
    with sub_create:
        pdf_key = None
        if pdf_mode:
            file_rec = get_exam_file(exam_id)
            pdf_key = get_pdf_key(file_rec) if file_rec else None
            if not pdf_key:
                st.error("Ujian PDF ini belum punya file/kunci. Unggah file PDF lewat ✏️ Edit PDF dulu.")
        source = st.radio("Sumber gambar sampul", ["Unggah gambar sendiri", "Gunakan gambar bawaan"],
                          horizontal=True, key="stego_src")
        cover_bytes, cover_name = None, None
        if source == "Unggah gambar sendiri":
            up = st.file_uploader("Gambar sampul (PNG/JPG/BMP/WEBP)", type=["png", "jpg", "jpeg", "bmp", "webp"],
                                  key="stego_cover_up")
            if up:
                cover_bytes, cover_name = up.getvalue(), up.name
        else:
            choice = st.selectbox("Gambar bawaan", [k for k, v in BUILTIN_COVERS.items() if os.path.exists(v)],
                                  key="stego_builtin")
            if choice:
                with open(BUILTIN_COVERS[choice], "rb") as f:
                    cover_bytes, cover_name = f.read(), os.path.basename(BUILTIN_COVERS[choice])
        if cover_bytes:
            st.image(cover_bytes, caption=f"Sampul: {cover_name}", width=320)
        label = st.text_input("Label token (mis. Kelas A / Sesi 1)", value="Token Kelas A", key="stego_label")

        can_create = cover_bytes is not None and (not pdf_mode or pdf_key)
        if st.button("🧬 Sisipkan Token ke Gambar", type="primary", disabled=not can_create, key="stego_create"):
            try:
                result = create_stego_token(exam, cover_bytes, label.strip() or "Token", current_user["id"], pdf_key)
            except ValueError as e:
                st.error(f"❌ {e}")
                result = None
            except Exception as e:
                st.error(f"❌ Gambar tidak bisa diproses: {e}")
                result = None
            if result:
                if token_mode(exam) != "stego":
                    execute_query("UPDATE exams SET token_mode='stego' WHERE id=%s", (exam_id,))
                    record(blockchain, "UPDATE_TOKEN_SETTINGS", "exam", exam_id, token_mode="stego",
                           editor=current_user["username"])
                record(blockchain, "CREATE_STEGO_TOKEN", "stego", result["id"], exam_id=exam_id,
                       label=label.strip(), creator=current_user["username"])
                st.session_state.stego_last = {"exam_id": exam_id, **result,
                                               "file_name": f"TOKEN_{exam['exam_code']}_{result['uid'][:8]}.png"}
                st.session_state.stego_settings_nonce = st.session_state.get("stego_settings_nonce", 0) + 1
                flash("🎉 Gambar token steganografi berhasil dibuat & disimpan terenkripsi di database. "
                      "Ujian ini sekarang mewajibkan gambar token.", balloons=True)
                st.rerun()
        elif not can_create and cover_bytes is None:
            st.caption("Pilih / unggah gambar sampul terlebih dahulu.")

        last = st.session_state.get("stego_last")
        if last and last["exam_id"] == exam_id:
            st.markdown("---")
            st.markdown("#### ✅ Hasil gambar token terbaru")
            used = last["payload_bits"] / last["capacity_bits"] * 100
            st.caption(f"Data tersisip: {last['payload_bits']:,} bit dari kapasitas {last['capacity_bits']:,} bit "
                       f"({used:.3f}%) · cuplikan ciphertext: `{last['cipher_preview']}…`".replace(",", "."))
            image_compare(last["cover_png"], last["png"], last["metrics"])
            st.download_button("⬇️ Unduh Gambar Token (PNG)", data=last["png"], file_name=last["file_name"],
                               mime="image/png", type="primary", key="stego_dl_last")
            st.info("📤 Bagikan file PNG ini ke mahasiswa **sebagai dokumen** (Google Drive / e-mail / WA dokumen). "
                    "Jangan diedit, di-crop, atau dikonversi ke JPG.")

    # ---------------- Daftar ----------------
    with sub_list:
        tokens = list_tokens(exam_id)
        if not tokens:
            st.info("Belum ada gambar token untuk ujian ini.")
        for t in tokens:
            with st.container(border=True):
                c_img, c_info = st.columns([1, 3])
                try:
                    cover_png, stego_png = token_images(t)
                except Exception:
                    cover_png = stego_png = None
                if stego_png:
                    c_img.image(stego_png, use_container_width=True)
                status = "🟢 Aktif" if t["is_active"] else f"🔴 Dicabut ({fmt_dt(t['revoked_at'])})"
                c_info.markdown(f"**{t['label']}** · {status}")
                c_info.caption(f"ID token: `{t['token_uid']}` · Dibuat: {t['created_at']} · "
                               f"{t['width']}×{t['height']} px · PSNR {t['psnr'] or '∞'} dB · "
                               f"berlaku: {describe_window(exam)}")
                c_info.caption(f"SHA-256 gambar: `{t['stego_sha256']}`")
                b1, b2, b3 = c_info.columns(3)
                if stego_png:
                    b1.download_button("⬇️ Unduh PNG", data=stego_png, mime="image/png",
                                       file_name=f"TOKEN_{exam['exam_code']}_{t['token_uid'][:8]}.png",
                                       key=f"stg_dl_{t['id']}", use_container_width=True)
                if t["is_active"]:
                    if b2.button("⛔ Cabut", key=f"stg_rev_{t['id']}", use_container_width=True):
                        set_active(t["id"], False)
                        record(blockchain, "REVOKE_STEGO_TOKEN", "stego", t["id"], editor=current_user["username"])
                        flash(f"⛔ Token '{t['label']}' dicabut. Gambar ini tidak bisa dipakai lagi.")
                        st.rerun()
                elif b2.button("♻️ Aktifkan", key=f"stg_act_{t['id']}", use_container_width=True):
                    set_active(t["id"], True)
                    record(blockchain, "ACTIVATE_STEGO_TOKEN", "stego", t["id"], editor=current_user["username"])
                    flash(f"♻️ Token '{t['label']}' diaktifkan kembali.")
                    st.rerun()
                if b3.button("🗑️ Hapus", key=f"stg_del_{t['id']}", use_container_width=True):
                    delete_token(t["id"])
                    blockchain.add_block({"event": "DELETE_STEGO_TOKEN", "asset": f"stego:{t['id']}",
                                          "asset_hash": None, "editor": current_user["username"]})
                    flash("🗑️ Gambar token dihapus.")
                    st.rerun()
                if cover_png and stego_png:
                    with c_info.expander("Bandingkan dengan gambar sampul"):
                        image_compare(cover_png, stego_png)

    # ---------------- Uji ----------------
    with sub_verify:
        st.markdown("Unggah gambar apa saja untuk memeriksa apakah gambar tersebut berisi token ujian yang sah. "
                    "Coba unggah **gambar sampul aslinya** — terlihat sama, tetapi akan ditolak.")
        test = st.file_uploader("Gambar yang diuji", type=["png", "jpg", "jpeg", "bmp", "webp"], key="stego_test")
        if test:
            st.image(test.getvalue(), width=300)
            info = inspect_image(test.getvalue())
            if not info["found"]:
                st.error(info["message"])
            else:
                p, row, ex = info["payload"], info["row"], info["exam"]
                if not row:
                    st.error("Token terbaca, tetapi sudah dihapus dari database.")
                else:
                    state, msg = window_state(ex) if ex else ("expired", "Ujian sudah dihapus.")
                    if row["is_active"] and state == "open":
                        st.success(f"✅ Gambar berisi token SAH untuk ujian **{ex['exam_code']} — {ex['title']}**.")
                    elif not row["is_active"]:
                        st.warning("⛔ Token terbaca, tetapi sudah DICABUT.")
                    else:
                        st.warning(msg)
                    st.markdown(
                        f"- Label: **{row['label']}**\n- ID token: `{p['uid']}`\n"
                        f"- Diterbitkan: {p.get('iat', '-')}\n"
                        f"- Berisi kunci PDF: {'ya' if p.get('k') else 'tidak'}\n"
                        f"- Masa berlaku ujian: {describe_window(ex) if ex else '-'}"
                    )
