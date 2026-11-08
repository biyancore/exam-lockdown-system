import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
import base64

def generate_aes_key():
    """Menghasilkan kunci AES 256-bit (32 bytes)."""
    return AESGCM.generate_key(bit_length=256)

def _ensure_32_byte_key(key_bytes):
    """Memastikan kunci AES selalu berukuran pas 32 bytes."""
    if isinstance(key_bytes, str):
        key_bytes = key_bytes.encode('utf-8')
    # Pad dengan b'\0' jika kurang dari 32, atau potong jika lebih dari 32
    return key_bytes.ljust(32, b'\0')[:32]

def aes_encrypt(plain_text, key_bytes):
    """
    Enkripsi teks menggunakan AES-256-GCM.
    """
    key_bytes = _ensure_32_byte_key(key_bytes)
    aesgcm = AESGCM(key_bytes)
    nonce = os.urandom(12) # Standar GCM nonce 12 bytes
    ciphertext = aesgcm.encrypt(nonce, plain_text.encode('utf-8'), None)
    
    # Gabungkan nonce dan ciphertext lalu encode base64 agar mudah disimpan di DB text
    encrypted_blob = nonce + ciphertext
    return base64.b64encode(encrypted_blob).decode('utf-8')

def aes_decrypt(encrypted_base64, key_bytes):
    """
    Dekripsi teks menggunakan AES-256-GCM.
    """
    try:
        key_bytes = _ensure_32_byte_key(key_bytes)
        aesgcm = AESGCM(key_bytes)
        encrypted_blob = base64.b64decode(encrypted_base64.encode('utf-8'))
        
        nonce = encrypted_blob[:12]
        ciphertext = encrypted_blob[12:]
        
        decrypted_bytes = aesgcm.decrypt(nonce, ciphertext, None)
        return decrypted_bytes.decode('utf-8')
    except Exception as e:
        return f"[Error Dekripsi AES: {str(e)}]"

def chacha20_encrypt_file(file_bytes, key_bytes=None):
    """
    Enkripsi file menggunakan ChaCha20-Poly1305.
    Mengembalikan base64 string untuk ciphertext dan key string asli.
    """
    if key_bytes is None:
        raw_key = ChaCha20Poly1305.generate_key()
    else:
        raw_key = _ensure_32_byte_key(key_bytes)
        
    chacha = ChaCha20Poly1305(raw_key)
    nonce = os.urandom(12)
    
    ciphertext = chacha.encrypt(nonce, file_bytes, None)
    
    # Simpan kunci dalam bentuk string UTF-8 agar mudah dibaca dan dicocokkan kembali
    if isinstance(key_bytes, str):
        stored_key_str = key_bytes
    else:
        stored_key_str = raw_key.decode('utf-8', errors='ignore')

    return base64.b64encode(nonce + ciphertext).decode('utf-8'), stored_key_str

def chacha20_decrypt_file(encrypted_base64, key_input):
    """
    Dekripsi file menggunakan ChaCha20-Poly1305 dengan penanganan kunci string/bytes yang fleksibel.
    """
    try:
        # Normalisasi kunci inputan (baik string password teks biasa maupun base64)
        if isinstance(key_input, str):
            key_bytes = _ensure_32_byte_key(key_input.encode('utf-8'))
        else:
            key_bytes = _ensure_32_byte_key(key_input)
            
        encrypted_blob = base64.b64decode(encrypted_base64.encode('utf-8'))
        
        nonce = encrypted_blob[:12]
        ciphertext = encrypted_blob[12:]
        
        chacha = ChaCha20Poly1305(key_bytes)
        decrypted_bytes = chacha.decrypt(nonce, ciphertext, None)
        return decrypted_bytes
    except Exception as e:
        print(f"Error ChaCha20 Decrypt: {e}")
        return None

# ===========================================================================
# Enkripsi FILE versi 2 (dipakai untuk semua file PDF baru)
#   kunci   = PBKDF2-HMAC-SHA256(kunci dosen, salt 16 byte, 200.000 iterasi)
#   cipher  = ChaCha20-Poly1305 (BERBEDA dari AES-GCM yang dipakai untuk teks)
#   format  = b"SRK2" | salt(16) | nonce(12) | ciphertext+tag(16)
# ===========================================================================
from cryptography.hazmat.primitives import hashes as _hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC as _PBKDF2HMAC

PDF_MAGIC = b"SRK2"
PDF_KDF_ITERATIONS = 200_000
PDF_KDF_LABEL = f"PBKDF2-HMAC-SHA256 ({PDF_KDF_ITERATIONS:,} iterasi)".replace(",", ".")


def _derive_file_key(password, salt):
    return _PBKDF2HMAC(algorithm=_hashes.SHA256(), length=32, salt=salt,
                       iterations=PDF_KDF_ITERATIONS).derive(password.encode("utf-8"))


def pdf_encrypt(file_bytes, password):
    """Enkripsi file -> string base64 (disimpan di DB)."""
    salt, nonce = os.urandom(16), os.urandom(12)
    ciphertext = ChaCha20Poly1305(_derive_file_key(password, salt)).encrypt(nonce, file_bytes, PDF_MAGIC)
    return base64.b64encode(PDF_MAGIC + salt + nonce + ciphertext).decode("utf-8")


def pdf_decrypt(encrypted_base64, password):
    """Dekripsi file. Mendukung format v2 dan format lama (kunci di-padding). None jika kunci salah."""
    try:
        blob = base64.b64decode(encrypted_base64.encode("utf-8"))
    except Exception:
        return None
    if blob.startswith(PDF_MAGIC):
        salt, nonce, ciphertext = blob[4:20], blob[20:32], blob[32:]
        try:
            return ChaCha20Poly1305(_derive_file_key(password, salt)).decrypt(nonce, ciphertext, PDF_MAGIC)
        except Exception:
            return None
    return chacha20_decrypt_file(encrypted_base64, password)


def describe_file_cipher(encrypted_base64):
    """Rincian struktur ciphertext untuk ditampilkan ke pengguna."""
    blob = base64.b64decode(encrypted_base64.encode("utf-8"))
    if blob.startswith(PDF_MAGIC):
        return {
            "versi": "SRK2",
            "algoritma": "ChaCha20-Poly1305 (AEAD)",
            "kdf": PDF_KDF_LABEL,
            "salt": blob[4:20].hex(),
            "nonce": blob[20:32].hex(),
            "tag": blob[-16:].hex(),
            "ukuran_ciphertext": len(blob) - 32,
            "ukuran_total": len(blob),
            "preview": blob[32:32 + 96],
        }
    return {
        "versi": "lama",
        "algoritma": "ChaCha20-Poly1305 (AEAD)",
        "kdf": "kunci di-padding (format lama)",
        "salt": "-",
        "nonce": blob[:12].hex(),
        "tag": blob[-16:].hex(),
        "ukuran_ciphertext": len(blob) - 12,
        "ukuran_total": len(blob),
        "preview": blob[12:12 + 96],
    }
