from modules.database import execute_query
from modules.auth import hash_password

def seed_users():
    # Password default untuk testing: "password123"
    hashed_pwd = hash_password("password123")
    
    users = [
        ("dosen_kripto", hashed_pwd, None, "proctor"),
        ("biyan_mahasiswa", hashed_pwd, None, "student")
    ]
    
    for username, pwd_hash, bio_path, role in users:
        query = """
            INSERT IGNORE INTO users (username, password_hash, biometric_path, role)
            VALUES (%s, %s, %s, %s)
        """
        execute_query(query, (username, pwd_hash, bio_path, role))
    
    print("Akun uji coba berhasil ditambahkan!")

if __name__ == "__main__":
    seed_users()