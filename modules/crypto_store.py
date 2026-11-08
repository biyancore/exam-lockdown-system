"""
Pusat kriptografi aplikasi SRIKANDI.

- Master key acak 256-bit disimpan di config/master.key (dibuat otomatis).
- Setiap jenis data memakai sub-kunci berbeda yang diturunkan dengan HKDF-SHA256
  (mis. "token", "pdf-key", "answers", "message", "stego-image", "biometric").
- SUPER ENKRIPSI teks = Extended Vigenère (klasik) -> AES-256-GCM (modern).
- Rahasia yang cukup diverifikasi (token teks) disimpan sebagai hash PBKDF2-SHA256 + salt.
"""
import base64
import hashlib
import hmac
import os
import secrets

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from modules.classic_cipher import extended_vigenere_encrypt, extended_vigenere_decrypt

CONFIG_DIR = "config"
MASTER_KEY_PATH = os.path.join(CONFIG_DIR, "master.key")
VIGENERE_KEY = "KeyVigenereUPN2026"
SE_PREFIX = "se1:"            # penanda nilai hasil super-enkripsi
AES_PREFIX = "aes1:"          # penanda nilai hasil AES-GCM (data biner)
PBKDF2_ITERATIONS = 200_000

_master = None
_key_cache = {}


def master_key():
    global _master
    if _master is None:
        os.makedirs(CONFIG_DIR, exist_ok=True)
        if not os.path.exists(MASTER_KEY_PATH):
            with open(MASTER_KEY_PATH, "wb") as f:
                f.write(secrets.token_bytes(32))
        with open(MASTER_KEY_PATH, "rb") as f:
            _master = f.read()
    return _master


def derive_key(purpose):
    """Sub-kunci 256-bit khusus untuk satu jenis data (HKDF-SHA256)."""
    if purpose not in _key_cache:
        _key_cache[purpose] = HKDF(
            algorithm=hashes.SHA256(), length=32,
            salt=b"SRIKANDI-HKDF-v1", info=purpose.encode("utf-8"),
        ).derive(master_key())
    return _key_cache[purpose]


# --------------------------------------------------------------------------- AES-GCM
def aes_encrypt_bytes(data, purpose):
    nonce = os.urandom(12)
    return nonce + AESGCM(derive_key(purpose)).encrypt(nonce, data, purpose.encode())


def aes_decrypt_bytes(blob, purpose):
    return AESGCM(derive_key(purpose)).decrypt(blob[:12], blob[12:], purpose.encode())


def aes_encrypt_b64(data, purpose):
    return AES_PREFIX + base64.b64encode(aes_encrypt_bytes(data, purpose)).decode()


def aes_decrypt_b64(value, purpose):
    if not value or not value.startswith(AES_PREFIX):
        raise ValueError("Bukan data AES aplikasi")
    return aes_decrypt_bytes(base64.b64decode(value[len(AES_PREFIX):]), purpose)


# --------------------------------------------------------------------------- SUPER ENKRIPSI
def _vigenere_layer(text):
    # UTF-8 -> latin-1 agar setiap karakter <= 255 (Vigenère mod 256 jadi lossless)
    return extended_vigenere_encrypt(text.encode("utf-8").decode("latin-1"), VIGENERE_KEY)


def super_encrypt_raw(text, purpose="text"):
    """Vigenère -> AES-GCM, hasil berupa bytes (dipakai untuk payload steganografi)."""
    return aes_encrypt_bytes(_vigenere_layer(text).encode("latin-1"), purpose)


def super_decrypt_raw(blob, purpose="text"):
    vig = aes_decrypt_bytes(blob, purpose).decode("latin-1")
    return extended_vigenere_decrypt(vig, VIGENERE_KEY).encode("latin-1").decode("utf-8")


def super_encrypt(text, purpose="text"):
    return SE_PREFIX + base64.b64encode(super_encrypt_raw(text or "", purpose)).decode()


def super_decrypt(value, purpose="text"):
    if not is_super_encrypted(value):
        raise ValueError("Bukan data super-enkripsi")
    return super_decrypt_raw(base64.b64decode(value[len(SE_PREFIX):]), purpose)


def is_super_encrypted(value):
    return isinstance(value, str) and value.startswith(SE_PREFIX)


def super_encrypt_steps(text, purpose="text"):
    """Rincian tiap lapisan super-enkripsi (untuk ditampilkan saat demo)."""
    vig = _vigenere_layer(text)
    final = super_encrypt(text, purpose)
    return {
        "plaintext": text,
        "vigenere_hex": vig.encode("latin-1").hex(),
        "aes_base64": final[len(SE_PREFIX):],
        "stored": final,
    }


# --------------------------------------------------------------------------- HASH
def hash_secret(secret):
    salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", secret.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    return f"pbkdf2_sha256${PBKDF2_ITERATIONS}${salt.hex()}${digest.hex()}"


def is_hashed(value):
    return isinstance(value, str) and value.startswith("pbkdf2_sha256$")


def verify_secret(stored, provided):
    if not stored or provided is None:
        return False
    if not is_hashed(stored):  # data lama (plaintext)
        return hmac.compare_digest(stored.encode(), provided.encode())
    try:
        _, iterations, salt_hex, digest_hex = stored.split("$")
        digest = hashlib.pbkdf2_hmac("sha256", provided.encode("utf-8"), bytes.fromhex(salt_hex), int(iterations))
        return hmac.compare_digest(digest.hex(), digest_hex)
    except (ValueError, TypeError):
        return False


def sha256_hex(data):
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()
