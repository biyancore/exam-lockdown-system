"""
Pesan antar pengguna.
- Subjek & isi pesan teks : SUPER ENKRIPSI (Extended Vigenère + AES-256-GCM).
- Lampiran "pesan gambar" : pesan rahasia disembunyikan di gambar (STEGANOGRAFI LSB).
  Pesan rahasia dienkripsi dulu (Vigenère + AES; opsional dengan sandi tambahan
  PBKDF2) sebelum disisipkan. File gambar disimpan di DB terenkripsi AES-GCM.
"""
import json
import os
from datetime import datetime

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from modules.crypto_store import aes_decrypt_b64, aes_encrypt_b64, super_decrypt, super_decrypt_raw, \
    super_encrypt, super_encrypt_raw
from modules.database import execute_query
from modules.modern_cipher import _derive_file_key
from modules.steganography import embed_bytes, extract_bytes, load_rgb, prepare_cover, to_png_bytes

MSG_PURPOSE = "message"
HIDDEN_PURPOSE = "message-hidden"
IMAGE_PURPOSE = "message-image"


def _wrap_with_password(blob, password):
    salt, nonce = os.urandom(16), os.urandom(12)
    return b"P1" + salt + nonce + AESGCM(_derive_file_key(password, salt)).encrypt(nonce, blob, b"msg")


def _unwrap_with_password(blob, password):
    salt, nonce, ct = blob[2:18], blob[18:30], blob[30:]
    return AESGCM(_derive_file_key(password, salt)).decrypt(nonce, ct, b"msg")


def make_stego_message_image(cover_source, hidden_text, password=""):
    """PNG berisi pesan rahasia terenkripsi."""
    blob = super_encrypt_raw(json.dumps({"t": hidden_text}), HIDDEN_PURPOSE)
    blob = (_wrap_with_password(blob, password) if password else b"P0" + blob)
    return to_png_bytes(embed_bytes(prepare_cover(load_rgb(cover_source), 1200), blob))


def read_stego_message(image_source, password=""):
    """(ok, teks/pesan_error)."""
    try:
        raw = extract_bytes(load_rgb(image_source))
    except Exception:
        return False, "File bukan gambar yang valid."
    if raw is None:
        return False, "Tidak ada pesan tersembunyi di gambar ini."
    try:
        if raw.startswith(b"P1"):
            if not password:
                return False, "Pesan tersembunyi dilindungi sandi. Masukkan sandinya."
            raw = _unwrap_with_password(raw, password)
        else:
            raw = raw[2:]
        return True, json.loads(super_decrypt_raw(raw, HIDDEN_PURPOSE))["t"]
    except Exception:
        return False, "Sandi salah atau data tersembunyi rusak."


def send_message(sender_id, receiver_id, subject, body, stego_png=None, protected=False):
    return execute_query(
        """
        INSERT INTO messages (sender_id, receiver_id, subject_enc, body_enc, stego_image_enc, stego_protected)
        VALUES (%s, %s, %s, %s, %s, %s)
        """,
        (sender_id, receiver_id, super_encrypt(subject, MSG_PURPOSE), super_encrypt(body, MSG_PURPOSE),
         aes_encrypt_b64(stego_png, IMAGE_PURPOSE) if stego_png else None, 1 if protected else 0),
        return_id=True,
    )


def _decorate(rows):
    out = []
    for r in rows:
        r = dict(r)
        try:
            r["subject"] = super_decrypt(r["subject_enc"], MSG_PURPOSE)
            r["body"] = super_decrypt(r["body_enc"], MSG_PURPOSE)
        except Exception:
            r["subject"], r["body"] = "[gagal didekripsi]", "[gagal didekripsi]"
        out.append(r)
    return out


def inbox(user):
    if user["role"] == "student":
        rows = execute_query(
            """
            SELECT m.*, s.username AS sender_name FROM messages m JOIN users s ON s.id = m.sender_id
            WHERE m.receiver_id = %s OR (m.receiver_id IS NULL AND s.role = 'proctor')
            ORDER BY m.id DESC
            """, (user["id"],), fetch=True)
    else:
        rows = execute_query(
            """
            SELECT m.*, s.username AS sender_name FROM messages m JOIN users s ON s.id = m.sender_id
            WHERE m.receiver_id = %s ORDER BY m.id DESC
            """, (user["id"],), fetch=True)
    return _decorate(rows or [])


def sent(user):
    rows = execute_query(
        """
        SELECT m.*, r.username AS receiver_name FROM messages m LEFT JOIN users r ON r.id = m.receiver_id
        WHERE m.sender_id = %s ORDER BY m.id DESC
        """, (user["id"],), fetch=True)
    return _decorate(rows or [])


def unread_count(user):
    row = execute_query(
        "SELECT COUNT(*) AS n FROM messages WHERE receiver_id = %s AND read_at IS NULL", (user["id"],)
    )
    return int(row["n"]) if row else 0


def mark_read(message_id, user_id):
    execute_query("UPDATE messages SET read_at = %s WHERE id = %s AND receiver_id = %s AND read_at IS NULL",
                  (datetime.now(), message_id, user_id))


def message_image(row):
    return aes_decrypt_b64(row["stego_image_enc"], IMAGE_PURPOSE) if row.get("stego_image_enc") else None


def delete_message(message_id, user_id):
    return execute_query("DELETE FROM messages WHERE id = %s AND (sender_id = %s OR receiver_id = %s)",
                         (message_id, user_id, user_id))
