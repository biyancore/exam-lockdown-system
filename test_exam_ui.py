"""Uji render halaman dosen dan mahasiswa dengan sesi sementara."""
from streamlit.testing.v1 import AppTest
import os
import json
from modules.database import execute_query
from modules.classic_cipher import extended_vigenere_encrypt, extended_vigenere_decrypt
from modules.modern_cipher import aes_encrypt, aes_decrypt


def check(role, menu):
    assert os.environ.get('SECURE_EXAM_DB') == 'secure_exam_e2e_codex', 'Gunakan database uji terpisah'
    user = execute_query("SELECT * FROM users WHERE role=%s LIMIT 1", (role,))
    assert user, f"Akun {role} tidak tersedia"
    app = AppTest.from_file('app.py', default_timeout=30)
    app.session_state.logged_in = True
    app.session_state.user = user
    app.session_state.active_exam = None
    app.session_state.current_question_idx = 0
    app.session_state.student_answers = {}
    app.session_state.editing_exam_id = None
    app.session_state.token_target_exam_id = None
    app.run()
    assert not app.exception, [e.message for e in app.exception]
    app.radio[0].set_value(menu).run()
    assert not app.exception, [e.message for e in app.exception]
    print(role, 'halaman berhasil dimuat')
    return app


def check_exam_save():
    app = check('proctor', '📝 Kelola Ujian')
    code = 'REGRESI-KODE-UNIK'
    other_code = 'REGRESI-KODE-LAIN'
    try:
        app.text_input[0].set_value(code)
        app.text_area[0].set_value('Pertanyaan uji penyimpanan')
        next(b for b in app.button if 'Terbitkan' in b.label).click().run()
        assert not app.exception, [e.message for e in app.exception]
        assert any('berhasil diterbitkan' in s.value for s in app.success), 'Pesan sukses hilang saat rerun'
        exam = execute_query('SELECT * FROM exams WHERE exam_code=%s', (code,))
        assert exam
        app.text_area[0].set_value('Draf tidak boleh hilang')
        next(b for b in app.button if 'Terbitkan' in b.label).click().run()
        assert any('sudah digunakan' in e.value for e in app.error), [e.value for e in app.error]
        assert app.text_area[0].value == 'Draf tidak boleh hilang'
        assert execute_query('SELECT * FROM exams WHERE id=%s', (exam['id'],)) == exam
        app.text_input[0].set_value(other_code)
        next(b for b in app.button if 'Terbitkan' in b.label).click().run()
        assert not app.exception
        assert execute_query('SELECT id FROM exams WHERE exam_code=%s', (other_code,))
        app.session_state.editing_exam_id = exam['id']
        app.run()
        app.text_input[0].set_value(other_code)
        next(b for b in app.button if 'Simpan Perubahan' in b.label).click().run()
        assert any('sudah digunakan' in e.value for e in app.error)
        app.text_input[0].set_value(code)
        next(b for b in app.button if 'Simpan Perubahan' in b.label).click().run()
        assert not app.exception
        assert any('berhasil diperbarui' in s.value for s in app.success)
        print('Kode unik, duplikat buat/edit, draf, dan notifikasi sukses: lulus')
    finally:
        execute_query('DELETE FROM exams WHERE exam_code IN (%s,%s)', (code, other_code))


def check_exam_edit_loaded():
    app = check('proctor', '📝 Kelola Ujian')
    codes = ('REGRESI-EDIT-ISI', 'REGRESI-EDIT-LAIN')
    questions = [dict(question=f'Pertanyaan tersimpan {i}',
                      options={k: f'Pilihan {k} nomor {i}' for k in 'ABCD'},
                      correct='ABCD'[i % 4]) for i in range(5)]
    def encrypt(q):
        return aes_encrypt(extended_vigenere_encrypt(json.dumps(q), 'KeyVigenereUPN2026'),
                           b'KunciAES32BytesPanjangPasBanget!!')
    try:
        for code, qs in zip(codes, (questions, questions[:1])):
            execute_query('INSERT INTO exams (exam_code,title,encrypted_question,encrypted_answer_key,duration_minutes) VALUES (%s,%s,%s,%s,%s)',
                          (code, code, encrypt(qs), json.dumps({i:q['correct'] for i,q in enumerate(qs)}), 45), raise_errors=True)
        app.run()  # Formulir baru sudah berisi widget kosong sebelum Edit.
        exam = execute_query('SELECT * FROM exams WHERE exam_code=%s', (codes[0],))
        app.button(key=f"edit_{exam['id']}").click().run()
        assert not app.exception
        assert not app.tabs, 'Edit harus langsung tampil tanpa tab Buat Ujian Baru'
        assert any('Edit Soal' in w.value for w in app.markdown)
        assert len(app.text_area) == 5
        for i, q in enumerate(questions):
            assert app.text_area[i].value == q['question'], 'Soal tersimpan tertimpa state formulir kosong'
            for k in 'ABCD':
                assert [w for w in app.text_input if w.label == k][i].value == q['options'][k]
            assert [w for w in app.selectbox if w.label == 'Kunci'][i].value == q['correct']
        app.number_input[0].set_value(6).run()
        assert len(app.text_area) == 6 and app.text_area[4].value == questions[4]['question']
        app.number_input[0].set_value(5).run()
        app.text_area[0].set_value('Pertanyaan setelah diedit')
        next(b for b in app.button if 'Simpan Perubahan' in b.label).click().run()
        assert not app.exception
        app.button(key=f"edit_{exam['id']}").click().run()
        assert app.text_area[0].value == 'Pertanyaan setelah diedit'
        next(b for b in app.button if 'Batal Edit' in b.label).click().run()
        assert app.tabs, 'Batal edit harus kembali ke halaman kelola ujian'
        other = execute_query('SELECT id FROM exams WHERE exam_code=%s', (codes[1],))
        app.button(key=f"edit_{other['id']}").click().run()
        app.run()  # AppTest menyisakan elemen lama setelah rerun yang mengurangi jumlah widget.
        assert len(app.text_area) == 1 and app.text_area[0].value == questions[0]['question'], ([w.value for w in app.text_area], app.session_state.editing_exam_id, [e.message for e in app.exception])
        app.text_area[0].set_value('Perubahan dibatalkan').run()
        next(b for b in app.button if 'Batal Edit' in b.label).click().run()
        app.button(key=f"edit_{other['id']}").click().run()
        assert app.text_area[0].value == questions[0]['question']
        stored = execute_query('SELECT encrypted_question FROM exams WHERE id=%s', (exam['id'],))
        saved = json.loads(extended_vigenere_decrypt(aes_decrypt(stored['encrypted_question'], b'KunciAES32BytesPanjangPasBanget!!'), 'KeyVigenereUPN2026'))
        assert len(saved) == 5 and saved[0]['question'] == 'Pertanyaan setelah diedit'
        print('Edit memuat soal/pilihan/kunci, tambah soal, simpan, pindah ujian, dan batal: lulus')
    finally:
        execute_query('DELETE FROM exams WHERE exam_code IN (%s,%s)', codes)


if __name__ == '__main__':
    check('proctor', '📝 Kelola Ujian')
    check('student', '📝 Ujian Saya')
    check_exam_save()
    check_exam_edit_loaded()
