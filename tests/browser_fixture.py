"""Data sintetis untuk pengujian browser, terpisah dari database mahasiswa."""
import argparse
import io
import sys
from pathlib import Path

import mysql.connector
from PIL import Image

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from modules.auth import hash_password

DB_NAME = 'secure_exam_e2e_codex'
OUT = Path('data/browser_test')


def make_pdf():
    stream = b'BT /F1 16 Tf 50 750 Td (Soal PDF Uji Kriptografi) Tj ET'
    objects = [
        b'<< /Type /Catalog /Pages 2 0 R >>',
        b'<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
        b'<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>',
        b'<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>',
        b'<< /Length ' + str(len(stream)).encode() + b' >>\nstream\n' + stream + b'\nendstream',
    ]
    result = bytearray(b'%PDF-1.4\n')
    offsets = [0]
    for i, obj in enumerate(objects, 1):
        offsets.append(len(result))
        result.extend(f'{i} 0 obj\n'.encode() + obj + b'\nendobj\n')
    xref = len(result)
    result.extend(f'xref\n0 {len(objects)+1}\n0000000000 65535 f \n'.encode())
    for offset in offsets[1:]:
        result.extend(f'{offset:010} 00000 n \n'.encode())
    result.extend(f'trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n'.encode())
    return bytes(result)


def setup():
    OUT.mkdir(parents=True, exist_ok=True)
    db = mysql.connector.connect(host='localhost', user='root', password='')
    cur = db.cursor()
    cur.execute(f'CREATE DATABASE IF NOT EXISTS {DB_NAME}')
    cur.execute(f'USE {DB_NAME}')
    cur.execute('CREATE TABLE IF NOT EXISTS codex_test_marker (id INT PRIMARY KEY)')
    cur.execute('INSERT IGNORE INTO codex_test_marker VALUES (1)')
    for table in ['users', 'exams', 'exam_files', 'student_submissions', 'stego_assets', 'blockchain_logs']:
        cur.execute(f'SHOW CREATE TABLE secure_exam_db.{table}')
        ddl = cur.fetchone()[1].replace('CREATE TABLE ', 'CREATE TABLE IF NOT EXISTS ', 1)
        cur.execute(ddl)
    for name, role in [('uji_dosen', 'proctor'), ('uji_mahasiswa', 'student'), ('uji_lain', 'student')]:
        cur.execute('INSERT IGNORE INTO users (username,password_hash,role) VALUES (%s,%s,%s)',
                    (name, hash_password('UjiLokal2026!'), role))
    db.commit()
    db.close()
    (OUT / 'soal.pdf').write_bytes(make_pdf())
    Image.new('RGB', (240, 160), '#d8ece2').save(OUT / 'sampul.png')
    Image.new('RGB', (8, 8), 'white').save(OUT / 'kecil.png')
    (OUT / 'palsu.pdf').write_bytes(b'Ini bukan PDF')
    print(f'Database uji {DB_NAME} dan berkas sintetis siap')


def cleanup():
    db = mysql.connector.connect(host='localhost', user='root', password='')
    cur = db.cursor()
    cur.execute(f'SELECT id FROM {DB_NAME}.codex_test_marker')
    assert cur.fetchall() == [(1,)], 'Penanda database uji tidak cocok'
    cur.execute(f'DROP DATABASE {DB_NAME}')
    db.close()
    print('Database uji terpisah sudah dihapus')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=['setup', 'cleanup'])
    args = parser.parse_args()
    setup() if args.action == 'setup' else cleanup()
