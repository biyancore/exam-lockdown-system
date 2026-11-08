import mysql.connector
from mysql.connector import Error

DB_CONFIG = {
    "host": "localhost",
    "database": "secure_exam_db",
    "user": "root",
    "password": "",  # Default XAMPP kosong
}

# Menyimpan pesan error terakhir agar UI bisa menampilkan penyebab kegagalan
_last_error = None


def get_last_error():
    """Mengembalikan pesan error MySQL terakhir (atau None)."""
    return _last_error


def _set_error(e):
    global _last_error
    _last_error = str(e) if e else None


def get_db_connection():
    """Membuat koneksi ke database MySQL XAMPP"""
    try:
        connection = mysql.connector.connect(**DB_CONFIG)
        if connection.is_connected():
            return connection
    except Error as e:
        _set_error(e)
        print(f"Gagal terhubung ke MySQL: {e}")
    return None


def execute_query(query, params=None, fetch=False, return_id=False):
    """
    Fungsi pembantu untuk menjalankan query INSERT, UPDATE, DELETE, atau SELECT.
    - SELECT  : fetch=True -> list of dict, fetch=False -> satu dict / None
    - lainnya : rowcount (atau lastrowid jika return_id=True). None jika gagal.
    """
    _set_error(None)
    connection = get_db_connection()
    if connection is None:
        return None

    cursor = connection.cursor(dictionary=True)
    result = None
    try:
        cursor.execute(query, params or ())
        if query.strip().upper().startswith("SELECT"):
            result = cursor.fetchall() if fetch else cursor.fetchone()
        else:
            connection.commit()
            result = cursor.lastrowid if return_id else cursor.rowcount
    except Error as e:
        _set_error(e)
        print(f"Error eksekusi query: {e}")
        result = None
    finally:
        cursor.close()
        connection.close()

    return result


def run_transaction(statements):
    """
    Menjalankan beberapa query (list of (query, params)) dalam satu transaksi.
    Semua berhasil -> commit & return True. Ada yang gagal -> rollback & return False.
    """
    _set_error(None)
    connection = get_db_connection()
    if connection is None:
        return False

    cursor = connection.cursor()
    try:
        for query, params in statements:
            cursor.execute(query, params or ())
        connection.commit()
        return True
    except Error as e:
        connection.rollback()
        _set_error(e)
        print(f"Error transaksi: {e}")
        return False
    finally:
        cursor.close()
        connection.close()


def _existing_columns(cursor, table):
    cursor.execute(
        """
        SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = %s
        """,
        (table,),
    )
    return {row[0] for row in cursor.fetchall()}


def ensure_schema():
    """Memastikan tabel dan kolom yang dibutuhkan aplikasi sudah ada di database.
    Setiap langkah dijalankan terpisah supaya satu kegagalan tidak membatalkan langkah lain."""
    connection = get_db_connection()
    if connection is None:
        return

    cursor = connection.cursor()

    def run(q, params=None):
        try:
            cursor.execute(q, params or ())
            connection.commit()
        except Error as e:
            print(f"[ensure_schema] {e}")

    # --- Kolom tambahan tabel exams ---
    run("ALTER TABLE exams ADD COLUMN IF NOT EXISTS duration_minutes INT DEFAULT 90")
    run("ALTER TABLE exams ADD COLUMN IF NOT EXISTS token_hash VARCHAR(255) DEFAULT NULL")

    # --- Tabel file PDF terenkripsi ---
    run("""
        CREATE TABLE IF NOT EXISTS exam_files (
            id INT AUTO_INCREMENT PRIMARY KEY,
            exam_id INT NOT NULL,
            encrypted_file LONGTEXT NOT NULL,
            file_key VARCHAR(255) NOT NULL,
            file_cipher_type VARCHAR(50) DEFAULT 'ChaCha20-Poly1305',
            CONSTRAINT exam_files_ibfk_1 FOREIGN KEY (exam_id) REFERENCES exams (id) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
    """)
    # Tabel exam_files versi lama (dari dump SQL) memakai kolom file_name/file_path
    # dan belum punya encrypted_file/file_key -> INSERT selalu gagal diam-diam.
    try:
        cols = _existing_columns(cursor, "exam_files")
    except Error:
        cols = set()
    if "encrypted_file" not in cols:
        run("ALTER TABLE exam_files ADD COLUMN encrypted_file LONGTEXT NULL")
    if "file_key" not in cols:
        run("ALTER TABLE exam_files ADD COLUMN file_key VARCHAR(255) NULL")
    if "file_name" in cols:
        run("ALTER TABLE exam_files MODIFY file_name VARCHAR(255) NULL DEFAULT NULL")
    if "file_path" in cols:
        run("ALTER TABLE exam_files MODIFY file_path VARCHAR(255) NULL DEFAULT NULL")

    # --- Tabel bank soal PG: SATU BARIS = SATU SOAL ---
    run("""
        CREATE TABLE IF NOT EXISTS exam_questions (
            id INT AUTO_INCREMENT PRIMARY KEY,
            exam_id INT NOT NULL,
            question_no INT NOT NULL,
            encrypted_question TEXT NOT NULL,
            encrypted_option_a TEXT NOT NULL,
            encrypted_option_b TEXT NOT NULL,
            encrypted_option_c TEXT NOT NULL,
            encrypted_option_d TEXT NOT NULL,
            encrypted_answer TEXT NOT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            UNIQUE KEY uq_exam_question (exam_id, question_no),
            CONSTRAINT exam_questions_ibfk_1 FOREIGN KEY (exam_id) REFERENCES exams (id) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
    """)

    # --- Token ujian: jenis token + masa berlaku + token terenkripsi ---
    run("ALTER TABLE exams ADD COLUMN IF NOT EXISTS token_mode VARCHAR(10) NOT NULL DEFAULT 'text'")
    run("ALTER TABLE exams ADD COLUMN IF NOT EXISTS token_encrypted TEXT NULL")
    run("ALTER TABLE exams ADD COLUMN IF NOT EXISTS token_valid_from DATETIME NULL")
    run("ALTER TABLE exams ADD COLUMN IF NOT EXISTS token_valid_until DATETIME NULL")

    # --- Metadata file PDF (nama, ukuran, hash SHA-256 isi asli, KDF) ---
    run("ALTER TABLE exam_files ADD COLUMN IF NOT EXISTS file_name VARCHAR(255) NULL")
    run("ALTER TABLE exam_files ADD COLUMN IF NOT EXISTS file_size INT NULL")
    run("ALTER TABLE exam_files ADD COLUMN IF NOT EXISTS file_sha256 CHAR(64) NULL")
    run("ALTER TABLE exam_files ADD COLUMN IF NOT EXISTS kdf VARCHAR(60) NULL")
    run("ALTER TABLE exam_files MODIFY file_key TEXT NULL")  # kunci kini disimpan terenkripsi

    # --- Biometrik wajah: template terenkripsi AES ---
    run("ALTER TABLE users ADD COLUMN IF NOT EXISTS biometric_template LONGTEXT NULL")
    run("ALTER TABLE users ADD COLUMN IF NOT EXISTS biometric_updated_at DATETIME NULL")

    # --- Token gambar steganografi (satu baris = satu gambar token) ---
    run("""
        CREATE TABLE IF NOT EXISTS exam_stego_tokens (
            id INT AUTO_INCREMENT PRIMARY KEY,
            token_uid CHAR(32) NOT NULL,
            exam_id INT NOT NULL,
            label VARCHAR(100) NOT NULL,
            cover_image_enc LONGTEXT NOT NULL,
            stego_image_enc LONGTEXT NOT NULL,
            cover_sha256 CHAR(64) NOT NULL,
            stego_sha256 CHAR(64) NOT NULL,
            secret_hash CHAR(64) NOT NULL,
            width INT NOT NULL,
            height INT NOT NULL,
            payload_bits INT NOT NULL,
            capacity_bits INT NOT NULL,
            psnr DECIMAL(7,2) NULL,
            is_active TINYINT(1) NOT NULL DEFAULT 1,
            created_by INT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            revoked_at DATETIME NULL,
            UNIQUE KEY uq_token_uid (token_uid),
            KEY idx_stego_exam (exam_id),
            CONSTRAINT exam_stego_tokens_ibfk_1 FOREIGN KEY (exam_id) REFERENCES exams (id) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
    """)

    # --- Pesan teks (super-enkripsi) + lampiran gambar steganografi ---
    run("""
        CREATE TABLE IF NOT EXISTS messages (
            id INT AUTO_INCREMENT PRIMARY KEY,
            sender_id INT NOT NULL,
            receiver_id INT NULL,
            subject_enc TEXT NOT NULL,
            body_enc LONGTEXT NOT NULL,
            stego_image_enc LONGTEXT NULL,
            stego_protected TINYINT(1) NOT NULL DEFAULT 0,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            read_at DATETIME NULL,
            KEY idx_msg_receiver (receiver_id),
            CONSTRAINT messages_ibfk_1 FOREIGN KEY (sender_id) REFERENCES users (id) ON DELETE CASCADE,
            CONSTRAINT messages_ibfk_2 FOREIGN KEY (receiver_id) REFERENCES users (id) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
    """)

    # --- Penanda migrasi satu kali ---
    run("""
        CREATE TABLE IF NOT EXISTS app_meta (
            meta_key VARCHAR(64) PRIMARY KEY,
            meta_value TEXT NULL
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
    """)

    # PDF disimpan sebagai base64 di LONGTEXT. Default XAMPP max_allowed_packet = 1MB,
    # sehingga PDF > ~700KB gagal disimpan. Naikkan ke 64MB (berlaku untuk koneksi baru).
    try:
        cursor.execute("SELECT @@GLOBAL.max_allowed_packet")
        current = cursor.fetchone()[0]
        if current < 64 * 1024 * 1024:
            cursor.execute("SET GLOBAL max_allowed_packet = 67108864")
    except Error as e:
        print(f"[ensure_schema] Tidak bisa menaikkan max_allowed_packet: {e}")

    cursor.close()
    connection.close()


def get_meta(key):
    row = execute_query("SELECT meta_value FROM app_meta WHERE meta_key = %s", (key,))
    return row["meta_value"] if row else None


def set_meta(key, value):
    return execute_query(
        "INSERT INTO app_meta (meta_key, meta_value) VALUES (%s, %s) "
        "ON DUPLICATE KEY UPDATE meta_value = VALUES(meta_value)",
        (key, value),
    )
