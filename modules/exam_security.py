"""Enkripsi PDF dan token gambar untuk ujian."""
import base64
import io
import json
import os
import secrets
import time

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from PIL import Image, UnidentifiedImageError

MAGIC = b"EXAMSTEG1"
MAX_PAYLOAD = 8192
MAX_PDF_BYTES = 10 * 1024 * 1024
MAX_IMAGE_PIXELS = 8_000_000


def derive_key(master_key, purpose):
    if len(master_key) != 32:
        raise ValueError("Kunci utama harus 32 byte")
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=purpose).derive(master_key)


def encrypt_pdf(data, master_key, exam_id):
    if len(data) > MAX_PDF_BYTES:
        raise ValueError("PDF maksimal 10 MB")
    if not data.startswith(b"%PDF-"):
        raise ValueError("File bukan PDF yang valid")
    nonce = os.urandom(12)
    return nonce + ChaCha20Poly1305(derive_key(master_key, b"exam-pdf-v1")).encrypt(
        nonce, data, str(exam_id).encode()
    )


def decrypt_pdf(data, master_key, exam_id):
    return ChaCha20Poly1305(derive_key(master_key, b"exam-pdf-v1")).decrypt(
        data[:12], data[12:], str(exam_id).encode()
    )


def create_token(master_key, exam_id, user_id, expires_at):
    payload = json.dumps({"exam": exam_id, "user": user_id, "expires": int(expires_at),
                          "id": secrets.token_hex(16)}, separators=(",", ":")).encode()
    classical_key = derive_key(master_key, b"exam-vigenere-v1")
    shifted = bytes((v + classical_key[i % len(classical_key)]) % 256 for i, v in enumerate(payload))
    nonce = os.urandom(12)
    encrypted = AESGCM(derive_key(master_key, b"exam-token-v1")).encrypt(nonce, shifted, None)
    return base64.urlsafe_b64encode(nonce + encrypted).decode("ascii")


def validate_token(token, master_key, exam_id, user_id, now=None):
    try:
        raw = base64.b64decode(token.encode("ascii"), altchars=b"-_", validate=True)
        shifted = AESGCM(derive_key(master_key, b"exam-token-v1")).decrypt(raw[:12], raw[12:], None)
        classical_key = derive_key(master_key, b"exam-vigenere-v1")
        plain = bytes((v - classical_key[i % len(classical_key)]) % 256 for i, v in enumerate(shifted))
        payload = json.loads(plain)
        if payload["exam"] != exam_id or payload["user"] != user_id:
            return None
        if payload["expires"] <= (time.time() if now is None else now):
            return None
        return payload
    except Exception:
        return None


def embed_token(image_bytes, token):
    payload = token.encode("ascii")
    if len(payload) > MAX_PAYLOAD:
        raise ValueError("Token terlalu besar")
    image = Image.open(io.BytesIO(image_bytes))
    if image.width * image.height > MAX_IMAGE_PIXELS:
        raise ValueError("Gambar maksimal 8 juta piksel")
    image = image.convert("RGB")
    data = bytearray(image.tobytes())
    message = MAGIC + len(payload).to_bytes(4, "big") + payload
    if len(message) * 8 > len(data):
        raise ValueError("Gambar terlalu kecil untuk token")
    for i in range(len(message) * 8):
        data[i] = (data[i] & 254) | ((message[i // 8] >> (7 - i % 8)) & 1)
    output = io.BytesIO()
    Image.frombytes("RGB", image.size, bytes(data)).save(output, format="PNG")
    return output.getvalue()


def extract_token(image_bytes):
    try:
        image = Image.open(io.BytesIO(image_bytes))
        if image.format != "PNG":
            raise ValueError("Gunakan gambar PNG asli")
        if image.width * image.height > MAX_IMAGE_PIXELS:
            raise ValueError("Gambar maksimal 8 juta piksel")
        data = image.convert("RGB").tobytes()
        def read_bytes(start, count):
            if (start + count) * 8 > len(data):
                raise ValueError("Gambar token tidak lengkap")
            return bytes(sum((data[(start + i) * 8 + bit] & 1) << (7 - bit)
                             for bit in range(8)) for i in range(count))
        header = read_bytes(0, len(MAGIC) + 4)
        length = int.from_bytes(header[len(MAGIC):], "big")
        if header[:len(MAGIC)] != MAGIC or not 0 < length <= MAX_PAYLOAD:
            raise ValueError("Token tidak ditemukan dalam gambar")
        return read_bytes(len(header), length).decode("ascii")
    except (UnidentifiedImageError, OSError, UnicodeError) as exc:
        raise ValueError("Gambar token tidak valid") from exc
