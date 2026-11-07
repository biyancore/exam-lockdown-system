"""Penyimpanan PDF terenkripsi dan gambar token di MySQL."""
import hashlib
import os
import secrets
import time
from pathlib import Path

from modules.database import get_db_connection
from modules.exam_security import create_token, decrypt_pdf, embed_token, encrypt_pdf, extract_token, validate_token

KEY_PATH = Path(os.environ.get("SECURE_EXAM_KEY_PATH", "config/exam_data.key"))


def master_key():
    KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
    # Do not silently replace a lost key when encrypted records already exist.
    if not KEY_PATH.exists():
        db = connection()
        try:
            cur = db.cursor()
            cur.execute("SELECT (SELECT COUNT(*) FROM secure_exam_pdfs) + (SELECT COUNT(*) FROM secure_exam_tokens)")
            if cur.fetchone()[0]:
                raise RuntimeError("Kunci enkripsi hilang. Pulihkan config/exam_data.key dari cadangan sebelum melanjutkan.")
        finally:
            db.close()
    try:
        with KEY_PATH.open("xb") as f:
            f.write(secrets.token_bytes(32))
    except FileExistsError:
        pass
    key = KEY_PATH.read_bytes()
    if len(key) != 32:
        raise ValueError("Kunci data ujian tidak valid")
    return key


def connection():
    db = get_db_connection()
    if db is None:
        raise RuntimeError("Tidak dapat terhubung ke database")
    return db


def ensure_tables():
    db = connection()
    try:
        cur = db.cursor()
        cur.execute("""CREATE TABLE IF NOT EXISTS secure_exam_pdfs (
            exam_id INT NOT NULL PRIMARY KEY, file_name VARCHAR(255) NOT NULL,
            encrypted_pdf LONGBLOB NOT NULL,
            FOREIGN KEY (exam_id) REFERENCES exams(id) ON DELETE CASCADE
        ) ENGINE=InnoDB""")
        cur.execute("""CREATE TABLE IF NOT EXISTS secure_exam_tokens (
            exam_id INT NOT NULL, user_id INT NOT NULL, token_digest BINARY(32) NOT NULL,
            image LONGBLOB NOT NULL, expires_at BIGINT NOT NULL, unlocked_at BIGINT DEFAULT NULL,
            PRIMARY KEY (exam_id, user_id),
            FOREIGN KEY (exam_id) REFERENCES exams(id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        ) ENGINE=InnoDB""")
        cur.execute("SHOW COLUMNS FROM secure_exam_tokens LIKE 'unlocked_at'")
        if not cur.fetchone():
            cur.execute("ALTER TABLE secure_exam_tokens ADD COLUMN unlocked_at BIGINT DEFAULT NULL")
        db.commit()
    finally:
        db.close()


def save_pdf(exam_id, filename, data):
    encrypted = encrypt_pdf(data, master_key(), exam_id)
    db = connection()
    try:
        cur = db.cursor()
        check_blob_size(cur, encrypted)
        cur.execute("INSERT INTO secure_exam_pdfs (exam_id,file_name,encrypted_pdf) VALUES (%s,%s,%s) ON DUPLICATE KEY UPDATE file_name=VALUES(file_name), encrypted_pdf=VALUES(encrypted_pdf)", (exam_id, os.path.basename(filename)[:255], encrypted))
        db.commit()
    finally:
        db.close()


def load_pdf(exam_id):
    db = connection()
    try:
        cur = db.cursor()
        cur.execute("SELECT file_name,encrypted_pdf FROM secure_exam_pdfs WHERE exam_id=%s", (exam_id,))
        row = cur.fetchone()
    finally:
        db.close()
    return (row[0], decrypt_pdf(row[1], master_key(), exam_id)) if row else None


def issue_token(exam_id, user_id, expires_at, cover):
    if expires_at <= time.time():
        raise ValueError("Masa berlaku token harus di masa depan")
    token = create_token(master_key(), exam_id, user_id, expires_at)
    image = embed_token(cover, token)
    db = connection()
    try:
        cur = db.cursor()
        check_blob_size(cur, image)
        cur.execute("SELECT role FROM users WHERE id=%s", (user_id,))
        user = cur.fetchone()
        if not user or user[0] != 'student':
            raise ValueError("Token hanya dapat diterbitkan untuk akun mahasiswa")
        cur.execute("INSERT INTO secure_exam_tokens (exam_id,user_id,token_digest,image,expires_at) VALUES (%s,%s,%s,%s,%s) ON DUPLICATE KEY UPDATE token_digest=VALUES(token_digest), image=VALUES(image), expires_at=VALUES(expires_at), unlocked_at=NULL", (exam_id, user_id, hashlib.sha256(token.encode()).digest(), image, expires_at))
        db.commit()
    finally:
        db.close()
    return image


def check_blob_size(cursor, data):
    cursor.execute("SELECT @@max_allowed_packet")
    packet_limit = cursor.fetchone()[0]
    # Bound SQL escaping as well as the BLOB so an oversized packet never closes the connection.
    if len(data) * 2 + 8192 >= packet_limit:
        raise ValueError(
            "Berkas terlalu besar untuk batas paket MySQL saat ini "
            f"({packet_limit // 1024:,} KB). Gunakan berkas lebih kecil atau "
            "naikkan max_allowed_packet pada konfigurasi MySQL, lalu mulai ulang MySQL."
        )


def verify_image(exam_id, user_id, image):
    token = extract_token(image)
    if not validate_token(token, master_key(), exam_id, user_id):
        return False
    db = connection()
    try:
        cur = db.cursor()
        cur.execute("UPDATE secure_exam_tokens SET unlocked_at=%s WHERE exam_id=%s AND user_id=%s AND token_digest=%s AND expires_at>%s", (int(time.time()), exam_id, user_id, hashlib.sha256(token.encode()).digest(), int(time.time())))
        cur.execute("SELECT token_digest FROM secure_exam_tokens WHERE exam_id=%s AND user_id=%s AND expires_at>%s", (exam_id, user_id, int(time.time())))
        row = cur.fetchone()
        db.commit()
    finally:
        db.close()
    return bool(row and secrets.compare_digest(row[0], hashlib.sha256(token.encode()).digest()))


def has_exam_access(exam_id, user_id):
    db = connection()
    try:
        cur = db.cursor()
        cur.execute("SELECT 1 FROM secure_exam_tokens WHERE exam_id=%s AND user_id=%s AND unlocked_at IS NOT NULL AND expires_at>%s", (exam_id, user_id, int(time.time())))
        return cur.fetchone() is not None
    finally:
        db.close()


def load_student_pdf(exam_id, user_id):
    if not has_exam_access(exam_id, user_id):
        raise PermissionError("Verifikasi token gambar terlebih dahulu atau minta token baru kepada dosen.")
    return load_pdf(exam_id)


def get_token_image(exam_id, user_id):
    db = connection()
    try:
        cur = db.cursor()
        cur.execute("SELECT image FROM secure_exam_tokens WHERE exam_id=%s AND user_id=%s", (exam_id, user_id))
        row = cur.fetchone()
        return row[0] if row else None
    finally:
        db.close()
