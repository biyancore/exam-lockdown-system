import mysql.connector
from mysql.connector import Error

def get_db_connection():
    """Membuat koneksi ke database MySQL XAMPP"""
    try:
        connection = mysql.connector.connect(
            host='localhost',
            database='secure_exam_db',
            user='root',
            password=''  # Default XAMPP kosong
        )
        if connection.is_connected():
            return connection
    except Error as e:
        print(f"Gagal terhubung ke MySQL: {e}")
        return None

def execute_query(query, params=None, fetch=False):
    """Fungsi pembantu untuk menjalankan query INSERT, UPDATE, DELETE, atau SELECT"""
    connection = get_db_connection()
    if connection is None:
        return None
    
    cursor = connection.cursor(dictionary=True)
    result = None
    try:
        cursor.execute(query, params or ())
        if query.strip().upper().startswith("SELECT"):
            if fetch:
                result = cursor.fetchall()
            else:
                result = cursor.fetchone()
        else:
            connection.commit()
            result = cursor.rowcount
    except Error as e:
        print(f"Error eksekusi query: {e}")
    finally:
        cursor.close()
        connection.close()
    
    return result

def ensure_schema():
    """Memastikan kolom tambahan yang dibutuhkan aplikasi sudah ada di database."""
    queries = [
        # Menambahkan kolom durasi dan token hash pada tabel exams jika belum ada
        """ALTER TABLE exams ADD COLUMN IF NOT EXISTS duration_minutes INT DEFAULT 90;""",
        """ALTER TABLE exams ADD COLUMN IF NOT EXISTS token_hash VARCHAR(255) DEFAULT NULL;""",
        # Memastikan tipe cipher file sesuai usulan (ChaCha20-Poly1305)
        """ALTER TABLE exam_files MODIFY COLUMN file_cipher_type VARCHAR(50) DEFAULT 'ChaCha20-Poly1305';"""
    ]
    
    connection = get_db_connection()
    if connection is None:
        return
    
    cursor = connection.cursor()
    try:
        for q in queries:
            cursor.execute(q)
        connection.commit()
    except Error as e:
        print(f"Error saat memastikan skema database: {e}")
    finally:
        cursor.close()
        connection.close()