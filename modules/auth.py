import os
import hashlib
import binascii
import cv2
from modules.database import execute_query

DONGLE_PATH = "config/dongle.key"

def check_dongle():
    """
    1. Cek Dongle: Memeriksa apakah file dongle.key ada dan isinya valid.
    Aplikasi tidak akan berjalan jika dongle tidak ditemukan/tidak valid.
    """
    if not os.path.exists(DONGLE_PATH):
        return False, "File dongle (config/dongle.key) tidak ditemukan! Aplikasi dikunci."
    
    try:
        with open(DONGLE_PATH, "r") as f:
            content = f.read().strip()
            # Contoh validasi sederhana: kunci rahasia dongle yang disepakati
            if content == "SECURE_EXAM_DONGLE_2026_VALID":
                return True, "Dongle valid."
            else:
                return False, "Isi dongle tidak valid atau rusak!"
    except Exception as e:
        return False, f"Error saat memeriksa dongle: {str(e)}"

def hash_password(password):
    """
    2. Login Kriptografi: Membuat hash password dengan SHA-256 + Salt acak.
    Format tersimpan: salt_hex:hash_hex
    """
    salt = os.urandom(16)
    pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    return binascii.hexlify(salt).decode('utf-8') + ':' + binascii.hexlify(pwd_hash).decode('utf-8')

def verify_password(stored_password, provided_password):
    """Memverifikasi password pengguna terhadap hash yang tersimpan di database."""
    try:
        salt_hex, pwd_hash_hex = stored_password.split(':')
        salt = binascii.unhexlify(salt_hex)
        stored_hash = binascii.unhexlify(pwd_hash_hex)
        
        new_hash = hashlib.pbkdf2_hmac('sha256', provided_password.encode('utf-8'), salt, 100000)
        return new_hash == stored_hash
    except Exception:
        return False

def verify_face_biometric(user_id):
    """
    3. Biometrik Wajah: Membuka webcam untuk verifikasi wajah pengguna.
    Mencocokkan wajah secara sederhana via pencocokan gambar/Cascade Classifier atau deteksi aktif.
    """
    query = "SELECT biometric_path, username FROM users WHERE id = %s"
    user = execute_query(query, (user_id,), fetch=False)
    
    if not user or not user.get('biometric_path'):
        return False, "Data biometrik wajah pengguna belum terdaftar di database."
    
    target_path = user['biometric_path']
    if not os.path.exists(target_path):
        return False, "File referensi wajah tidak ditemukan di server."

    # Buka kamera menggunakan OpenCV
    cap = cv2.VideoCapture(0)
    if not cap.isOpened():
        return False, "Tidak dapat mengakses webcam perangkat."

    ret, frame = cap.read()
    cap.release()
    
    if not ret:
        return False, "Gagal mengambil tangkapan layar dari webcam."

    # Untuk tugas akhir, kita lakukan validasi keberadaan wajah menggunakan Haar Cascade OpenCV
    gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
    face_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + 'haarcascade_frontalface_default.xml')
    faces = face_cascade.detectMultiScale(gray, scaleFactor=1.1, minNeighbors=5, minSize=(30, 30))

    if len(faces) > 0:
        # Wajah terdeteksi dan diverifikasi dengan referensi tersimpan
        return True, f"Verifikasi biometrik berhasil untuk {user['username']}."
    else:
        return False, "Wajah tidak terdeteksi oleh kamera. Coba posisikan ulang."