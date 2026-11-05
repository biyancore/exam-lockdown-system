import hashlib
import json
from datetime import datetime
from modules.database import execute_query

class SimpleBlockchain:
    """Implementasi Blockchain Sederhana untuk mencatat log aktivitas & rekap nilai ujian."""
    
    def __init__(self):
        self.ensure_genesis_block()

    def get_latest_block(self):
        """Mengambil blok terakhir dari database."""
        query = "SELECT * FROM blockchain_logs ORDER BY block_index DESC LIMIT 1;"
        result = execute_query(query, fetch=False)
        return result

    def ensure_genesis_block(self):
        """Membuat Genesis Block (Blok pertama) jika blockchain masih kosong."""
        latest = self.get_latest_block()
        if not latest:
            timestamp = str(datetime.now())
            data_payload = json.dumps({"event": "GENESIS_BLOCK", "description": "Inisialisasi Rantai Blockchain Secure Exam"})
            previous_hash = "0" * 64
            current_hash = self.calculate_hash(0, timestamp, data_payload, previous_hash)
            
            query = """
                INSERT INTO blockchain_logs (block_index, timestamp, data_payload, previous_hash, current_hash)
                VALUES (%s, %s, %s, %s, %s)
            """
            execute_query(query, (0, timestamp, data_payload, previous_hash, current_hash))

    def calculate_hash(self, index, timestamp, data_payload, previous_hash):
        """Menghitung hash SHA-256 untuk sebuah blok."""
        block_string = f"{index}{timestamp}{data_payload}{previous_hash}"
        return hashlib.sha256(block_string.encode('utf-8')).hexdigest()

    def add_block(self, data_dict):
        """Menambahkan blok baru ke rantai blockchain."""
        latest_block = self.get_latest_block()
        
        new_index = latest_block['block_index'] + 1
        previous_hash = latest_block['current_hash']
        timestamp = str(datetime.now())
        data_payload = json.dumps(data_dict, ensure_ascii=False)
        
        current_hash = self.calculate_hash(new_index, timestamp, data_payload, previous_hash)
        
        query = """
            INSERT INTO blockchain_logs (block_index, timestamp, data_payload, previous_hash, current_hash)
            VALUES (%s, %s, %s, %s, %s)
        """
        rows = execute_query(query, (new_index, timestamp, data_payload, previous_hash, current_hash))
        return rows is not None and rows > 0

    def validate_chain(self):
        """
        Memvalidasi integritas seluruh rantai blockchain.
        Mengembalikan True jika rantai valid, atau False jika ada manipulasi data.
        """
        query = "SELECT * FROM blockchain_logs ORDER BY block_index ASC;"
        chain = execute_query(query, fetch=True)
        
        if not chain:
            return True, "Blockchain kosong."

        for i in range(1, len(chain)):
            current_block = chain[i]
            previous_block = chain[i-1]
            
            # 1. Cek apakah previous_hash sesuai dengan hash blok sebelumnya
            if current_block['previous_hash'] != previous_block['current_hash']:
                return False, f"Integritas rusak pada Blok {current_block['block_index']}: Previous hash tidak cocok!"
            
            # 2. Cek apakah current_hash valid dihitung ulang
            recalculated_hash = self.calculate_hash(
                current_block['block_index'],
                current_block['timestamp'],
                current_block['data_payload'],
                current_block['previous_hash']
            )
            if current_block['current_hash'] != recalculated_hash:
                return False, f"Integritas rusak pada Blok {current_block['block_index']}: Hash data telah dimanipulasi!"
                
        return True, "Rantai blockchain valid dan aman."