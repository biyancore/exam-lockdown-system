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
    """
    if key_bytes is None:
        key_bytes = ChaCha20Poly1305.generate_key()
    else:
        key_bytes = _ensure_32_byte_key(key_bytes)
        
    chacha = ChaCha20Poly1305(key_bytes)
    nonce = os.urandom(12)
    
    ciphertext = chacha.encrypt(nonce, file_bytes, None)
    return base64.b64encode(nonce + ciphertext).decode('utf-8'), base64.b64encode(key_bytes).decode('utf-8')

def chacha20_decrypt_file(encrypted_base64, key_base64):
    """
    Dekripsi file menggunakan ChaCha20-Poly1305.
    """
    try:
        key_bytes = base64.b64decode(key_base64.encode('utf-8'))
        encrypted_blob = base64.b64decode(encrypted_base64.encode('utf-8'))
        
        nonce = encrypted_blob[:12]
        ciphertext = encrypted_blob[12:]
        
        chacha = ChaCha20Poly1305(key_bytes)
        decrypted_bytes = chacha.decrypt(nonce, ciphertext, None)
        return decrypted_bytes
    except Exception as e:
        return None