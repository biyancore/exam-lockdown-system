"""Masa berlaku token ujian — berlaku untuk SEMUA jenis token
(token teks PG, kunci PDF, dan gambar token steganografi)."""
from datetime import datetime

BULAN = ["Jan", "Feb", "Mar", "Apr", "Mei", "Jun", "Jul", "Agu", "Sep", "Okt", "Nov", "Des"]

TOKEN_MODE_LABEL = {
    "text": "🔤 Token Teks",
    "stego": "🖼️ Token Gambar Steganografi",
}


def fmt_dt(dt):
    if not dt:
        return "-"
    return f"{dt.day:02d} {BULAN[dt.month - 1]} {dt.year} {dt.hour:02d}:{dt.minute:02d}"


def window_state(exam, now=None):
    """('open' | 'not_yet' | 'expired', pesan) untuk token sebuah ujian."""
    now = now or datetime.now()
    start, end = exam.get("token_valid_from"), exam.get("token_valid_until")
    if start and now < start:
        return "not_yet", f"⏳ Token belum berlaku. Token dapat dipakai mulai **{fmt_dt(start)}**."
    if end and now > end:
        return "expired", f"⌛ Token sudah kedaluwarsa sejak **{fmt_dt(end)}**. Hubungi dosen."
    return "open", "✅ Token sedang berlaku."


def describe_window(exam):
    start, end = exam.get("token_valid_from"), exam.get("token_valid_until")
    if not start and not end:
        return "Tanpa batas waktu"
    if start and end:
        return f"{fmt_dt(start)} – {fmt_dt(end)}"
    if start:
        return f"Mulai {fmt_dt(start)} (tanpa batas akhir)"
    return f"Sampai {fmt_dt(end)}"


def status_badge(exam):
    state, _ = window_state(exam)
    icon = {"open": "🟢", "not_yet": "🟡", "expired": "🔴"}[state]
    text = {"open": "Berlaku", "not_yet": "Belum berlaku", "expired": "Kedaluwarsa"}[state]
    return f"{icon} {text} · {describe_window(exam)}"


def token_mode(exam):
    mode = exam.get("token_mode") or "text"
    return mode if mode in TOKEN_MODE_LABEL else "text"
