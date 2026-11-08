"""Akses ujian: token teks, kunci PDF, token gambar, dan container file .enc."""
import base64
import json

from modules.crypto_store import (
    hash_secret, is_super_encrypted, sha256_hex, super_decrypt, super_encrypt, verify_secret,
)
from modules.database import execute_query, run_transaction
from modules.modern_cipher import PDF_KDF_LABEL, describe_file_cipher, pdf_decrypt, pdf_encrypt
from modules.stego_token import verify_stego_token
from modules.token_policy import window_state

ENC_MAGIC = b"SRIKANDI-ENC/1\n"


def is_pdf_exam(exam):
    return (exam or {}).get("token_hash") == "PDF_MODE"


# --------------------------------------------------------------------------- token teks
def text_token_plain(exam):
    """Token teks asli (untuk ditampilkan ke dosen)."""
    value = exam.get("token_encrypted")
    if is_super_encrypted(value):
        try:
            return super_decrypt(value, "token")
        except Exception:
            return None
    if exam.get("token_hash") and not str(exam["token_hash"]).startswith("pbkdf2_sha256$") and not is_pdf_exam(exam):
        return exam["token_hash"]  # data lama yang belum dimigrasi
    return None


def text_token_columns(token):
    """(token_hash, token_encrypted) untuk disimpan di tabel exams."""
    return hash_secret(token), super_encrypt(token, "token")


def verify_text_token(exam, token):
    state, msg = window_state(exam)
    if state != "open":
        return False, msg
    if not token or not verify_secret(exam.get("token_hash"), token.strip()):
        return False, "❌ Token salah!"
    return True, "✅ Token valid!"


def update_validity(exam_id, valid_from, valid_until):
    return execute_query(
        "UPDATE exams SET token_valid_from = %s, token_valid_until = %s WHERE id = %s",
        (valid_from, valid_until, exam_id),
    )


# --------------------------------------------------------------------------- file PDF
def get_exam_file(exam_id):
    return execute_query(
        """
        SELECT * FROM exam_files
        WHERE exam_id = %s AND encrypted_file IS NOT NULL AND encrypted_file <> ''
        ORDER BY id DESC LIMIT 1
        """,
        (exam_id,),
    )


def get_pdf_key(file_rec):
    """Kunci PDF tersimpan terenkripsi (super-enkripsi); format lama berupa teks polos."""
    value = (file_rec or {}).get("file_key")
    if not value:
        return None
    if is_super_encrypted(value):
        return super_decrypt(value, "pdf-key")
    return value


def save_exam_file(exam_id, pdf_bytes, key, file_name):
    """Enkripsi PDF (ChaCha20-Poly1305 + PBKDF2) dan simpan; selalu tepat satu baris per ujian."""
    return run_transaction([
        ("DELETE FROM exam_files WHERE exam_id = %s", (exam_id,)),
        ("""
            INSERT INTO exam_files
                (exam_id, encrypted_file, file_key, file_cipher_type, file_name, file_size, file_sha256, kdf)
            VALUES (%s, %s, %s, 'ChaCha20-Poly1305', %s, %s, %s, %s)
        """, (exam_id, pdf_encrypt(pdf_bytes, key), super_encrypt(key, "pdf-key"),
              (file_name or "soal.pdf")[:255], len(pdf_bytes), sha256_hex(pdf_bytes), PDF_KDF_LABEL)),
    ])


def decrypt_with_key(file_rec, key):
    candidates = [key]
    if key.strip() != key:
        candidates.append(key.strip())
    for candidate in candidates:
        data = pdf_decrypt(file_rec["encrypted_file"], candidate)
        if data:
            return data
    return None


def unlock_pdf_with_key(exam, file_rec, key):
    state, msg = window_state(exam)
    if state != "open":
        return None, msg
    if not key or not key.strip():
        return None, "⚠️ Masukkan kunci dosen terlebih dahulu!"
    data = decrypt_with_key(file_rec, key)
    if data is None:
        return None, "❌ Kunci salah! File gagal didekripsi."
    return data, "✅ Kunci benar! File berhasil didekripsi."


def unlock_pdf_with_stego(exam, file_rec, image_source):
    ok, msg, payload = verify_stego_token(exam, image_source)
    if not ok:
        return None, msg
    data = pdf_decrypt(file_rec["encrypted_file"], payload.get("k", ""))
    if data is None:
        return None, "❌ Gambar token valid, tetapi kunci PDF sudah diganti dosen. Minta gambar token yang baru."
    return data, msg + " File berhasil didekripsi dengan kunci yang tersembunyi di gambar."


def integrity_note(file_rec, data):
    expected = file_rec.get("file_sha256")
    if not expected:
        return None
    if sha256_hex(data) == expected:
        return "🛡️ Integritas file terverifikasi (SHA-256 cocok dengan saat diunggah)."
    return "⚠️ SHA-256 file berbeda dengan saat diunggah!"


# --------------------------------------------------------------------------- container .enc
def build_enc_file(exam, file_rec):
    """File .enc = header JSON (info publik) + ciphertext biner. Isi soal tetap terenkripsi."""
    info = describe_file_cipher(file_rec["encrypted_file"])
    header = {
        "format": "SRIKANDI-ENC/1",
        "exam_id": exam["id"],
        "exam_code": exam["exam_code"],
        "title": exam["title"],
        "cipher": info["algoritma"],
        "kdf": info["kdf"],
        "token_mode": exam.get("token_mode") or "text",
        "plaintext_sha256": file_rec.get("file_sha256"),
        "plaintext_size": file_rec.get("file_size"),
        "original_name": file_rec.get("file_name"),
    }
    blob = base64.b64decode(file_rec["encrypted_file"])
    return ENC_MAGIC + json.dumps(header).encode("utf-8") + b"\n" + blob


def parse_enc_file(data):
    """(header, ciphertext_base64). Header None untuk file .enc format lama (base64 polos)."""
    if data.startswith(ENC_MAGIC):
        rest = data[len(ENC_MAGIC):]
        line, _, blob = rest.partition(b"\n")
        return json.loads(line.decode("utf-8")), base64.b64encode(blob).decode()
    try:
        text = data.decode("ascii").strip()
        base64.b64decode(text, validate=True)
        return None, text
    except Exception:
        raise ValueError("Bukan file .enc SRIKANDI.")
