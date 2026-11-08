"""
Token ujian berbentuk GAMBAR STEGANOGRAFI.

Alur pembuatan (dosen):
  1. Buat rahasia acak (128-bit) + ID token unik.
  2. Payload JSON {uid, exam, code, s(rahasia), [k = kunci PDF]} -> SUPER ENKRIPSI
     (Vigenère + AES-256-GCM).
  3. Ciphertext disisipkan ke LSB gambar sampul -> gambar stego (PNG).
  4. Database hanya menyimpan SHA-256 rahasia, hash gambar, dan kedua gambar
     dalam bentuk terenkripsi AES. Pembuatan token dicatat di blockchain.

Alur verifikasi (mahasiswa):
  ekstrak LSB -> dekripsi -> cocokkan ID & hash rahasia dengan database ->
  cek token belum dicabut, milik ujian ini, dan masih dalam masa berlaku.
Gambar sampul asli (meski terlihat sama) tidak berisi token, jadi ditolak.
"""
import json
import secrets
from datetime import datetime

from modules.crypto_store import (
    aes_decrypt_b64, aes_encrypt_b64, sha256_hex, super_decrypt_raw, super_encrypt_raw,
)
from modules.database import execute_query
from modules.steganography import (
    capacity_bits, embed_bytes, extract_bytes, image_metrics, load_rgb,
    payload_bits, prepare_cover, to_png_bytes,
)
from modules.token_policy import window_state

PAYLOAD_PURPOSE = "stego-token"
IMAGE_PURPOSE = "stego-image"


def create_stego_token(exam, cover_source, label, created_by, pdf_key=None):
    """Membuat gambar token. Return dict berisi id, uid, png, cover_png, metrics."""
    cover = prepare_cover(load_rgb(cover_source))
    uid = secrets.token_hex(16)
    secret = secrets.token_hex(16)
    payload = {
        "v": 1, "uid": uid, "exam": int(exam["id"]), "code": exam["exam_code"],
        "s": secret, "iat": datetime.now().isoformat(timespec="seconds"),
    }
    if pdf_key:
        payload["k"] = pdf_key
    blob = super_encrypt_raw(json.dumps(payload, separators=(",", ":")), PAYLOAD_PURPOSE)

    stego = embed_bytes(cover, blob)  # ValueError jika kapasitas tidak cukup
    cover_png, stego_png = to_png_bytes(cover), to_png_bytes(stego)
    metrics = image_metrics(cover, stego)
    psnr = None if metrics["psnr"] == float("inf") else round(metrics["psnr"], 2)

    new_id = execute_query(
        """
        INSERT INTO exam_stego_tokens
            (token_uid, exam_id, label, cover_image_enc, stego_image_enc, cover_sha256, stego_sha256,
             secret_hash, width, height, payload_bits, capacity_bits, psnr, created_by)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """,
        (
            uid, exam["id"], label[:100], aes_encrypt_b64(cover_png, IMAGE_PURPOSE),
            aes_encrypt_b64(stego_png, IMAGE_PURPOSE), sha256_hex(cover_png), sha256_hex(stego_png),
            sha256_hex(secret), cover.size[0], cover.size[1], payload_bits(len(blob)),
            capacity_bits(cover), psnr, created_by,
        ),
        return_id=True,
    )
    if not new_id:
        return None
    return {
        "id": new_id, "uid": uid, "png": stego_png, "cover_png": cover_png,
        "metrics": metrics, "payload_bits": payload_bits(len(blob)), "capacity_bits": capacity_bits(cover),
        "cipher_preview": blob[:48].hex(),
    }


def read_token_payload(image_source):
    """(payload | None, kode_alasan). Alasan: ok, bad_image, no_token, tampered."""
    try:
        img = load_rgb(image_source)
    except Exception:
        return None, "bad_image"
    raw = extract_bytes(img)
    if raw is None:
        return None, "no_token"
    try:
        return json.loads(super_decrypt_raw(raw, PAYLOAD_PURPOSE)), "ok"
    except Exception:
        return None, "tampered"


REASON_MESSAGES = {
    "bad_image": "❌ File bukan gambar yang valid.",
    "no_token": "❌ Gambar ini tidak berisi token ujian. Pastikan Anda memakai gambar token "
                "asli dari dosen (bukan gambar sampul / hasil screenshot / foto yang dikompres).",
    "tampered": "❌ Data tersembunyi di gambar rusak atau palsu (gagal didekripsi).",
}


def verify_stego_token(exam, image_source, check_window=True):
    """(ok, pesan, payload). Payload berisi 'k' (kunci PDF) untuk ujian PDF."""
    payload, reason = read_token_payload(image_source)
    if payload is None:
        return False, REASON_MESSAGES[reason], None

    row = execute_query("SELECT * FROM exam_stego_tokens WHERE token_uid = %s", (payload.get("uid", ""),))
    if not row:
        return False, "❌ Gambar token tidak terdaftar atau sudah dihapus oleh dosen.", None
    if int(row["exam_id"]) != int(exam["id"]) or int(payload.get("exam", -1)) != int(exam["id"]):
        return False, f"❌ Gambar ini adalah token untuk ujian lain (kode `{payload.get('code', '?')}`).", None
    if sha256_hex(payload.get("s", "")) != row["secret_hash"]:
        return False, "❌ Rahasia di dalam gambar tidak cocok dengan database.", None
    if not row["is_active"]:
        return False, "❌ Gambar token ini sudah dicabut (dinonaktifkan) oleh dosen.", None
    if check_window:
        state, msg = window_state(exam)
        if state != "open":
            return False, msg, None
    return True, f"✅ Token gambar valid ({row['label']}).", payload


def inspect_image(image_source):
    """Untuk alat uji dosen: penjelasan lengkap isi gambar."""
    payload, reason = read_token_payload(image_source)
    if payload is None:
        return {"found": False, "message": REASON_MESSAGES[reason]}
    row = execute_query("SELECT * FROM exam_stego_tokens WHERE token_uid = %s", (payload.get("uid", ""),))
    exam = execute_query("SELECT * FROM exams WHERE id = %s", (payload.get("exam"),))
    return {"found": True, "payload": payload, "row": row, "exam": exam}


def list_tokens(exam_id=None):
    if exam_id:
        return execute_query(
            "SELECT * FROM exam_stego_tokens WHERE exam_id = %s ORDER BY id DESC", (exam_id,), fetch=True
        ) or []
    return execute_query("SELECT * FROM exam_stego_tokens ORDER BY id DESC", fetch=True) or []


def active_token_count(exam_id):
    row = execute_query(
        "SELECT COUNT(*) AS n FROM exam_stego_tokens WHERE exam_id = %s AND is_active = 1", (exam_id,)
    )
    return int(row["n"]) if row else 0


def token_images(row):
    """(cover_png, stego_png) hasil dekripsi dari database."""
    return aes_decrypt_b64(row["cover_image_enc"], IMAGE_PURPOSE), aes_decrypt_b64(row["stego_image_enc"], IMAGE_PURPOSE)


def set_active(token_id, active):
    return execute_query(
        "UPDATE exam_stego_tokens SET is_active = %s, revoked_at = %s WHERE id = %s",
        (1 if active else 0, None if active else datetime.now(), token_id),
    )


def revoke_all_for_exam(exam_id):
    return execute_query(
        "UPDATE exam_stego_tokens SET is_active = 0, revoked_at = %s WHERE exam_id = %s AND is_active = 1",
        (datetime.now(), exam_id),
    )


def delete_token(token_id):
    return execute_query("DELETE FROM exam_stego_tokens WHERE id = %s", (token_id,))
