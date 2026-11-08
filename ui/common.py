"""Komponen UI bersama."""
from datetime import datetime, timedelta

import streamlit as st

from modules.token_policy import fmt_dt


def render_header(title, subtitle):
    st.markdown(f"""
    <div class="page-header">
        <h1>{title}</h1>
        <p>{subtitle}</p>
    </div>
    """, unsafe_allow_html=True)


def flash(message, kind="success", balloons=False):
    """Simpan notifikasi untuk ditampilkan SETELAH st.rerun()."""
    st.session_state.flash = {"message": message, "kind": kind, "balloons": balloons}


def show_flash():
    data = st.session_state.pop("flash", None)
    if not data:
        return
    getattr(st, data["kind"])(data["message"])
    st.toast(data["message"], icon="🎉" if data.get("balloons") else ("✅" if data["kind"] == "success" else "⚠️"))
    if data.get("balloons"):
        st.balloons()


def tab_css(key):
    """Radio horizontal yang tampil seperti tab (bisa dipindah lewat kode).
    Mendukung struktur DOM radio Streamlit lama (label langsung) dan baru (stRadioOption)."""
    k = f".st-key-{key}"
    return f"""
<style>
{k} div[role="radiogroup"] {{
    display: flex; flex-wrap: wrap; gap: 4px;
    border-bottom: 2px solid #e2e8f0; margin-bottom: 12px;
}}
{k} div[role="radiogroup"] > label,
{k} label[data-testid="stRadioOption"] {{
    padding: 10px 18px !important; margin: 0 !important; cursor: pointer;
    border-radius: 8px 8px 0 0; border-bottom: 3px solid transparent;
}}
{k} div[role="radiogroup"] > label > div:first-child,
{k} label[data-testid="stRadioOption"] > div > div:first-child:not([data-testid]) {{ display: none !important; }}
{k} div[role="radiogroup"] label p {{ font-weight: 600 !important; color: #64748b !important; }}
{k} div[role="radiogroup"] label:hover {{ background: #f0fdf4; }}
{k} div[role="radiogroup"] > label:has(input:checked),
{k} label[data-testid="stRadioOption"]:has(input:checked) {{
    background: #e0f2e9; border-bottom-color: #1a7f5a;
}}
{k} div[role="radiogroup"] label:has(input:checked) p {{ color: #1a7f5a !important; }}
</style>
"""


def validity_editor(prefix, valid_from=None, valid_until=None, in_form=False):
    """
    Pengaturan masa berlaku token. Return (aktif, mulai, akhir).
    Di dalam st.form semua isian selalu tampil (form tidak rerun saat checkbox diubah).
    """
    now = datetime.now().replace(second=0, microsecond=0)
    start = valid_from or now
    end = valid_until or (start + timedelta(hours=2))
    st.session_state.setdefault(f"{prefix}_vlimit", bool(valid_from or valid_until))
    st.session_state.setdefault(f"{prefix}_vd1", start.date())
    st.session_state.setdefault(f"{prefix}_vt1", start.time())
    st.session_state.setdefault(f"{prefix}_vd2", end.date())
    st.session_state.setdefault(f"{prefix}_vt2", end.time())

    use = st.checkbox("⏳ Batasi masa berlaku token", key=f"{prefix}_vlimit",
                      help="Jika tidak dicentang, token berlaku tanpa batas waktu.")
    if use or in_form:
        if in_form:
            st.caption("Tanggal & jam di bawah hanya dipakai jika kotak di atas dicentang.")
        c1, c2, c3, c4 = st.columns(4)
        d1 = c1.date_input("Mulai (tanggal)", key=f"{prefix}_vd1", format="DD/MM/YYYY")
        t1 = c2.time_input("Mulai (jam)", key=f"{prefix}_vt1", step=300)
        d2 = c3.date_input("Berakhir (tanggal)", key=f"{prefix}_vd2", format="DD/MM/YYYY")
        t2 = c4.time_input("Berakhir (jam)", key=f"{prefix}_vt2", step=300)
        return use, datetime.combine(d1, t1), datetime.combine(d2, t2)
    return False, None, None


def validate_window(use, start, end):
    """(error | None, mulai, akhir) — None/None berarti tanpa batas."""
    if not use:
        return None, None, None
    if end <= start:
        return "Waktu berakhir token harus setelah waktu mulai.", None, None
    if end <= datetime.now():
        return f"Waktu berakhir ({fmt_dt(end)}) sudah lewat. Pilih waktu di masa depan.", None, None
    return None, start, end


def image_compare(cover_png, stego_png, metrics=None, extra_caption=""):
    """Tampilan perbandingan gambar sampul vs gambar stego."""
    from modules.crypto_store import sha256_hex
    from modules.steganography import diff_map, image_metrics, load_rgb, lsb_plane

    cover, stego = load_rgb(cover_png), load_rgb(stego_png)
    metrics = metrics or image_metrics(cover, stego)
    c1, c2 = st.columns(2)
    c1.image(cover_png, caption="Gambar sampul (asli)", use_container_width=True)
    c2.image(stego_png, caption="Gambar token (stego) — terlihat sama", use_container_width=True)
    psnr = "∞" if metrics["psnr"] == float("inf") else f"{metrics['psnr']:.2f} dB"
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("PSNR", psnr, help="> 40 dB berarti perbedaan tidak terlihat oleh mata")
    m2.metric("MSE", f"{metrics['mse']:.5f}")
    m3.metric("Piksel berubah", f"{metrics['changed_pixels']:,}".replace(",", "."))
    m4.metric("Perubahan maks / kanal", f"±{metrics['max_diff']}")
    st.markdown(
        f"| | SHA-256 |\n|---|---|\n| Sampul | `{sha256_hex(cover_png)}` |\n| Stego | `{sha256_hex(stego_png)}` |"
    )
    st.caption("Hash berbeda → isi file berbeda, walau secara kasat mata sama. " + extra_caption)
    with st.expander("🔬 Lihat analisis bit (LSB plane & peta perubahan)"):
        a, b, c = st.columns(3)
        a.image(lsb_plane(cover), caption="Bidang LSB sampul", use_container_width=True)
        b.image(lsb_plane(stego), caption="Bidang LSB stego (pola data di kiri atas)", use_container_width=True)
        c.image(diff_map(cover, stego), caption="Piksel yang berubah (merah)", use_container_width=True)
