from modules.database import get_db_connection

db = get_db_connection()
if db and db.is_connected():
    print("Yey! Koneksi ke database MySQL berhasil terhubung dengan sempurna!")
    db.close()
else:
    print("Aduh, koneksi gagal. Cek apakah MySQL di XAMPP sudah di-Start.")