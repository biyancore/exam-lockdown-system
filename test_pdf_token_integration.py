"""Uji alur PDF dan token menggunakan ujian sementara di database lokal."""
import io
import os
import time
import uuid
from PIL import Image
from modules.database import get_db_connection
from modules.exam_storage import ensure_tables, save_pdf, load_pdf, load_student_pdf, has_exam_access, issue_token, verify_image, get_token_image


def main():
    assert os.environ.get('SECURE_EXAM_DB') == 'secure_exam_e2e_codex', 'Gunakan database uji terpisah'
    ensure_tables()
    db = get_db_connection()
    if db is None:
        raise RuntimeError("Database tidak tersedia")
    cur = db.cursor()
    cur.execute("SELECT id FROM users WHERE role='student' LIMIT 1")
    student = cur.fetchone()
    if not student:
        raise RuntimeError("Tidak ada akun mahasiswa untuk pengujian")
    cur.execute("INSERT INTO exams (exam_code,title,encrypted_question,encrypted_answer_key) VALUES (%s,%s,%s,%s)",
                ('TEST-' + uuid.uuid4().hex, 'Ujian sementara pengujian', 'test', 'test'))
    exam_id = cur.lastrowid
    db.commit()
    try:
        pdf = b'%PDF-1.4\n% temporary integration test\n%%EOF\n'
        save_pdf(exam_id, 'soal.pdf', pdf)
        assert load_pdf(exam_id) == ('soal.pdf', pdf)
        cur.execute('SELECT encrypted_pdf FROM secure_exam_pdfs WHERE exam_id=%s', (exam_id,))
        assert pdf not in cur.fetchone()[0]
        cover = io.BytesIO()
        Image.new('RGB', (150, 150), 'white').save(cover, format='PNG')
        image = issue_token(exam_id, student[0], int(time.time()) + 60, cover.getvalue())
        assert get_token_image(exam_id, student[0]) == image
        assert not has_exam_access(exam_id, student[0])
        try:
            load_student_pdf(exam_id, student[0])
        except PermissionError:
            pass
        else:
            raise AssertionError('PDF terbuka tanpa verifikasi token')
        assert verify_image(exam_id, student[0], image)
        assert has_exam_access(exam_id, student[0])
        assert load_student_pdf(exam_id, student[0]) == ('soal.pdf', pdf)
        assert not verify_image(exam_id, student[0] + 1000000, image)
        replacement = issue_token(exam_id, student[0], int(time.time()) + 60, cover.getvalue())
        assert not has_exam_access(exam_id, student[0])
        assert not verify_image(exam_id, student[0], image)
        assert verify_image(exam_id, student[0], replacement)
        cur.execute('UPDATE secure_exam_tokens SET expires_at=%s WHERE exam_id=%s', (int(time.time()) - 1, exam_id))
        db.commit()
        assert not has_exam_access(exam_id, student[0])
        assert not verify_image(exam_id, student[0], replacement)
        cur.execute('SELECT @@max_allowed_packet')
        if cur.fetchone()[0] == 1048576:
            try:
                save_pdf(exam_id, 'large.pdf', b'%PDF-' + b'x' * 600000)
            except ValueError as exc:
                assert 'batas paket MySQL' in str(exc)
            else:
                raise AssertionError('Berkas melebihi batas paket tidak ditolak')
            assert load_pdf(exam_id) == ('soal.pdf', pdf)
        print('Lulus: penyimpanan PDF, pembatasan akses, penolakan akun lain, penggantian token, kedaluwarsa, dan batas paket MySQL')
    finally:
        cur.execute('DELETE FROM exams WHERE id=%s', (exam_id,))
        db.commit()
        db.close()


if __name__ == '__main__':
    main()
