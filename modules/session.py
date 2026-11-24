"""
Sesi login & penguncian verifikasi wajah.

Token sesi (disimpan di URL agar tahan refresh) = username | kedaluwarsa | amr | epoch | HMAC-SHA256
  - amr   : cara login yang SUDAH dilewati ("pwd" = password saja, "face" = password + wajah).
            Token "pwd" milik akun yang kini memakai biometrik TIDAK bisa langsung masuk,
            tetapi diarahkan ke langkah verifikasi wajah (menutup celah bypass Face ID lewat URL lama).
  - epoch : nomor sesi per pengguna (tabel app_meta). Logout mengganti epoch, sehingga semua
            salinan URL sesi lama (riwayat browser, tangkapan layar, dsb.) langsung tidak berlaku.

Penguncian wajah: gagal 3x berturut-turut -> akun dikunci 5 menit. Disimpan di database (bukan
st.session_state), jadi tidak bisa direset hanya dengan login ulang / membuka tab baru.
"""
import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from datetime import datetime, timedelta

from modules.database import execute_query, get_meta, set_meta

SESSION_PARAM = "exam_session"
SESSION_TTL = 60 * 60 * 24 * 7
SECRET_PATH = os.path.join("config", "session.key")
AMR_PASSWORD = "pwd"
AMR_FACE = "face"

FACE_MAX_ATTEMPTS = 3
FACE_LOCK_MINUTES = 5

_secret = None


def _session_secret():
    global _secret
    if _secret is None:
        os.makedirs("config", exist_ok=True)
        if not os.path.exists(SECRET_PATH):
            with open(SECRET_PATH, "wb") as f:
                f.write(secrets.token_bytes(32))
        with open(SECRET_PATH, "rb") as f:
            _secret = f.read()
    return _secret


def _sign(payload):
    return hmac.new(_session_secret(), payload.encode(), hashlib.sha256).hexdigest()


def _epoch(user_id):
    return get_meta(f"session_epoch:{user_id}") or "0"


def issue_token(user, amr):
    payload = f"{user['username']}|{int(time.time()) + SESSION_TTL}|{amr}|{_epoch(user['id'])}"
    return base64.urlsafe_b64encode(f"{payload}|{_sign(payload)}".encode()).decode()


def restore_token(token):
    """(user, amr) jika token sah & masih berlaku, selain itu (None, None)."""
    if not token:
        return None, None
    try:
        raw = base64.urlsafe_b64decode(token.encode()).decode()
        username, expires, amr, epoch, signature = raw.rsplit("|", 4)
    except (ValueError, TypeError, UnicodeDecodeError):
        return None, None  # termasuk token format lama (tanpa amr/epoch)
    payload = f"{username}|{expires}|{amr}|{epoch}"
    if not hmac.compare_digest(signature, _sign(payload)):
        return None, None
    if not expires.isdigit() or int(expires) < int(time.time()) or amr not in (AMR_PASSWORD, AMR_FACE):
        return None, None
    user = execute_query("SELECT * FROM users WHERE username = %s", (username,))
    if not user or not hmac.compare_digest(epoch, _epoch(user["id"])):
        return None, None
    return user, amr


def revoke_all(user_id):
    """Dipanggil saat logout: semua token sesi lama milik pengguna ini menjadi tidak berlaku."""
    set_meta(f"session_epoch:{user_id}", secrets.token_hex(8))


def public_user(user):
    """Data minimal untuk disimpan selama langkah verifikasi wajah (tanpa hash password / template)."""
    return {"id": user["id"], "username": user["username"], "role": user["role"]}


# --------------------------------------------------------------------------- penguncian wajah
def _lock_key(user_id):
    return f"face_fail:{user_id}"


def _lock_state(user_id):
    try:
        data = json.loads(get_meta(_lock_key(user_id)) or "{}")
    except ValueError:
        data = {}
    until = data.get("until")
    return int(data.get("n", 0)), (datetime.fromisoformat(until) if until else None)


def face_lock_remaining(user_id):
    """Sisa detik penguncian (0 jika tidak terkunci)."""
    _, until = _lock_state(user_id)
    if until and until > datetime.now():
        return int((until - datetime.now()).total_seconds()) + 1
    return 0


def face_attempts(user_id):
    n, until = _lock_state(user_id)
    if until and until <= datetime.now():  # masa kunci habis -> mulai dari nol
        reset_face_failures(user_id)
        return 0
    return n


def register_face_failure(user_id):
    """Catat 1 kegagalan. Return (jumlah_gagal, terkunci?)."""
    n = face_attempts(user_id) + 1
    data = {"n": n}
    if n >= FACE_MAX_ATTEMPTS:
        data["until"] = (datetime.now() + timedelta(minutes=FACE_LOCK_MINUTES)).isoformat(timespec="seconds")
    set_meta(_lock_key(user_id), json.dumps(data))
    return n, n >= FACE_MAX_ATTEMPTS


def reset_face_failures(user_id):
    execute_query("DELETE FROM app_meta WHERE meta_key = %s", (_lock_key(user_id),))


def fmt_wait(seconds):
    m, s = divmod(max(0, int(seconds)), 60)
    return f"{m} menit {s} detik" if m else f"{s} detik"
