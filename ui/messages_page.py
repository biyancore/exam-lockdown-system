"""Halaman Pesan: teks super-enkripsi + pesan gambar steganografi."""
import os

import streamlit as st

from modules.crypto_store import super_encrypt_steps
from modules.database import execute_query, get_last_error
from modules.messages import (
    delete_message, inbox, make_stego_message_image, mark_read, message_image, read_stego_message,
    send_message, sent,
)
from ui.common import flash, image_compare, render_header, show_flash, tab_css

TABS = ["📥 Kotak Masuk", "✉️ Tulis Pesan", "📤 Terkirim", "🖼️ Baca Pesan Gambar"]
BROADCAST = 0


def render(current_user, blockchain):
    render_header("Pesan Aman", "Pesan teks disuper-enkripsi (Vigenère + AES-256-GCM) · Pesan gambar memakai steganografi LSB")
    st.markdown(tab_css("msg_tab"), unsafe_allow_html=True)
    if st.session_state.get("msg_tab") not in TABS:
        st.session_state.msg_tab = TABS[0]
    tab = st.radio("Menu pesan", TABS, key="msg_tab", horizontal=True, label_visibility="collapsed")
    show_flash()
    if tab == TABS[0]:
        render_list(current_user, inbox(current_user), incoming=True)
    elif tab == TABS[1]:
        render_compose(current_user, blockchain)
    elif tab == TABS[2]:
        render_list(current_user, sent(current_user), incoming=False)
    else:
        render_reader()


def render_list(user, rows, incoming):
    if not rows:
        st.info("Belum ada pesan.")
        return
    for m in rows:
        unread = incoming and m.get("receiver_id") == user["id"] and not m.get("read_at")
        who = (f"Dari **{m['sender_name']}**" if incoming else
               f"Kepada **{m.get('receiver_name') or 'Semua Mahasiswa (broadcast)'}**")
        badge = " 🆕" if unread else ""
        attach = " · 🖼️ lampiran gambar" if m.get("stego_image_enc") else ""
        with st.expander(f"{'🔵 ' if unread else ''}{m['subject']} — {m['created_at']}{badge}"):
            if unread:
                mark_read(m["id"], user["id"])
            st.caption(who + (" · broadcast" if m.get("receiver_id") is None and incoming else "") + attach)
            st.markdown(m["body"])
            with st.popover("🔍 Lihat ciphertext di database"):
                st.caption("subject_enc")
                st.code(m["subject_enc"], language="text")
                st.caption("body_enc")
                st.code(m["body_enc"][:600] + ("…" if len(m["body_enc"]) > 600 else ""), language="text")
            img = message_image(m)
            if img:
                st.image(img, caption="Pesan gambar (berisi pesan rahasia tersembunyi)", width=320)
                c1, c2 = st.columns(2)
                c1.download_button("⬇️ Unduh gambar", data=img, file_name=f"pesan_{m['id']}.png", mime="image/png",
                                   key=f"msg_dl_{m['id']}")
                pw = ""
                if m.get("stego_protected"):
                    pw = c2.text_input("Sandi pesan tersembunyi", type="password", key=f"msg_pw_{m['id']}",
                                       autocomplete="new-password")
                if st.button("🔓 Ekstrak pesan tersembunyi", key=f"msg_ex_{m['id']}"):
                    ok, text = read_stego_message(img, pw)
                    (st.success if ok else st.error)(("🔓 Pesan rahasia: " + text) if ok else text)
            if st.button("🗑️ Hapus pesan", key=f"msg_del_{m['id']}"):
                delete_message(m["id"], user["id"])
                flash("🗑️ Pesan dihapus.")
                st.rerun()


def render_compose(user, blockchain):
    if user["role"] == "proctor":
        students = execute_query("SELECT id, username FROM users WHERE role='student' ORDER BY username", fetch=True) or []
        options = [BROADCAST] + [s["id"] for s in students]
        names = {BROADCAST: "📢 Semua Mahasiswa (broadcast)", **{s["id"]: s["username"] for s in students}}
    else:
        proctors = execute_query("SELECT id, username FROM users WHERE role='proctor' ORDER BY username", fetch=True) or []
        options = [p["id"] for p in proctors]
        names = {p["id"]: f"👨‍🏫 {p['username']}" for p in proctors}
    if not options:
        st.info("Belum ada penerima yang tersedia.")
        return

    receiver = st.selectbox("Kepada", options, format_func=lambda i: names[i], key="msg_to")
    subject = st.text_input("Subjek", key="msg_subject")
    body = st.text_area("Isi pesan", key="msg_body", height=140)
    attach = st.checkbox("🖼️ Lampirkan pesan gambar (pesan rahasia disembunyikan di dalam gambar)", key="msg_attach")
    cover_bytes = hidden = password = None
    if attach:
        src = st.radio("Gambar sampul", ["Unggah gambar", "Gambar bawaan"], horizontal=True, key="msg_src")
        if src == "Unggah gambar":
            up = st.file_uploader("Gambar sampul", type=["png", "jpg", "jpeg", "bmp", "webp"], key="msg_cover")
            cover_bytes = up.getvalue() if up else None
        else:
            with open(os.path.join("assets", "default_exam_bg.jpg"), "rb") as f:
                cover_bytes = f.read()
        hidden = st.text_area("Pesan rahasia yang disembunyikan di gambar", key="msg_hidden")
        password = st.text_input("Sandi tambahan (opsional, PBKDF2 + AES)", type="password", key="msg_hidden_pw",
                                 autocomplete="new-password")

    if subject or body:
        with st.expander("🔬 Pratinjau super-enkripsi isi pesan"):
            steps = super_encrypt_steps(body or subject)
            st.markdown("**1. Plaintext**")
            st.code(steps["plaintext"][:300], language="text")
            st.markdown("**2. Setelah Extended Vigenère (klasik) — hex**")
            st.code(steps["vigenere_hex"][:300], language="text")
            st.markdown("**3. Setelah AES-256-GCM (modern) — disimpan di database**")
            st.code(steps["stored"][:300], language="text")

    if not st.button("📨 Kirim Pesan Terenkripsi", type="primary", key="msg_send"):
        return
    if not subject.strip() or not body.strip():
        st.error("Subjek dan isi pesan wajib diisi.")
        return
    stego_png = None
    if attach:
        if not cover_bytes or not (hidden or "").strip():
            st.error("Untuk pesan gambar, pilih gambar sampul dan isi pesan rahasianya.")
            return
        try:
            stego_png = make_stego_message_image(cover_bytes, hidden.strip(), password or "")
        except Exception as e:
            st.error(f"Gagal membuat pesan gambar: {e}")
            return
    msg_id = send_message(user["id"], None if receiver == BROADCAST else receiver, subject.strip(), body.strip(),
                          stego_png, bool(password))
    if not msg_id:
        st.error(f"Gagal mengirim: {get_last_error()}")
        return
    blockchain.add_block({"event": "SEND_MESSAGE", "message_id": msg_id, "sender": user["username"],
                          "to": names[receiver], "stego_attachment": bool(stego_png)})
    if stego_png:
        st.session_state.msg_last_stego = (cover_bytes, stego_png)
    for k in ("msg_subject", "msg_body", "msg_hidden", "msg_hidden_pw", "msg_attach"):
        st.session_state.pop(k, None)
    flash("📨 Pesan terkirim dan tersimpan terenkripsi di database.", balloons=False)
    st.rerun()


def render_reader():
    st.markdown("Unggah gambar pesan (PNG) untuk mengekstrak pesan rahasia yang disembunyikan di dalamnya.")
    up = st.file_uploader("Gambar pesan", type=["png", "bmp", "jpg", "jpeg", "webp"], key="msg_reader")
    pw = st.text_input("Sandi (jika ada)", type="password", key="msg_reader_pw", autocomplete="new-password")
    if up and st.button("🔓 Ekstrak", key="msg_reader_go"):
        ok, text = read_stego_message(up.getvalue(), pw)
        (st.success if ok else st.error)(("🔓 Pesan rahasia: " + text) if ok else text)
    last = st.session_state.get("msg_last_stego")
    if last:
        with st.expander("🔬 Perbandingan gambar pesan terakhir yang Anda kirim"):
            from modules.steganography import load_rgb, prepare_cover, to_png_bytes
            image_compare(to_png_bytes(prepare_cover(load_rgb(last[0]), 1200)), last[1])
