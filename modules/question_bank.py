"""
Bank soal Pilihan Ganda per-soal.

Setiap soal disimpan sebagai SATU BARIS di tabel `exam_questions`.
Setiap kolom (pertanyaan, opsi A-D, kunci jawaban) dienkripsi berlapis:
    plaintext -> Extended Vigenère -> AES-256-GCM -> base64

Kolom `exams.encrypted_question` (blob gabungan) tetap diperbarui supaya
data lama/kode lain yang masih membacanya tidak rusak.
"""
import json

from modules.database import execute_query, run_transaction
from modules.modern_cipher import aes_encrypt, aes_decrypt
from modules.classic_cipher import extended_vigenere_encrypt, extended_vigenere_decrypt
from modules.crypto_store import super_encrypt, super_decrypt, is_super_encrypted

AES_KEY = b"KunciAES32BytesPanjangPasBanget!!"
VIGENERE_KEY = "KeyVigenereUPN2026"
OPTION_KEYS = ["A", "B", "C", "D"]


# ---------------------------------------------------------------------------
# Enkripsi per kolom
# ---------------------------------------------------------------------------
def _aes_decrypt_strict(cipher_b64):
    result = aes_decrypt(cipher_b64, AES_KEY)
    if result.startswith("[Error Dekripsi AES"):
        raise ValueError(result)
    return result


def encrypt_field(text):
    """Vigenère + AES untuk satu nilai teks.
    Teks diubah ke byte UTF-8 dulu (dipetakan ke latin-1) supaya karakter non-ASCII
    seperti tanda kutip miring atau emoji tidak rusak oleh Vigenère mod 256."""
    byte_str = (text or "").encode("utf-8").decode("latin-1")
    vig = extended_vigenere_encrypt(byte_str, VIGENERE_KEY)
    return aes_encrypt(vig, AES_KEY)


def decrypt_field(cipher_b64):
    vig = _aes_decrypt_strict(cipher_b64)
    byte_str = extended_vigenere_decrypt(vig, VIGENERE_KEY)
    return byte_str.encode("latin-1").decode("utf-8")


# ---------------------------------------------------------------------------
# Format blob lama (exams.encrypted_question)
# ---------------------------------------------------------------------------
def encrypt_legacy_blob(questions):
    # ensure_ascii=True -> JSON murni ASCII, aman untuk Vigenère mod 256
    raw_json = json.dumps(questions, ensure_ascii=True)
    return aes_encrypt(extended_vigenere_encrypt(raw_json, VIGENERE_KEY), AES_KEY)


def decrypt_legacy_blob(blob):
    dec_aes = _aes_decrypt_strict(blob)
    return json.loads(extended_vigenere_decrypt(dec_aes, VIGENERE_KEY))


def _answer_key_json(questions):
    """Kunci jawaban disimpan dengan SUPER ENKRIPSI (dulu JSON polos)."""
    plain = json.dumps({str(i): q.get("correct", "A") for i, q in enumerate(questions)})
    return super_encrypt(plain, "answer-key")


def load_answer_key(stored):
    """Membaca kunci jawaban (format super-enkripsi atau JSON lama)."""
    if is_super_encrypted(stored):
        return json.loads(super_decrypt(stored, "answer-key"))
    return json.loads(stored or "{}")


def normalize_question(q):
    opts = q.get("options") or {}
    correct = q.get("correct", "A")
    return {
        "question": q.get("question", "") or "",
        "options": {k: opts.get(k, "") or "" for k in OPTION_KEYS},
        "correct": correct if correct in OPTION_KEYS else "A",
    }


# ---------------------------------------------------------------------------
# Baca / tulis
# ---------------------------------------------------------------------------
def count_questions(exam_id):
    row = execute_query("SELECT COUNT(*) AS n FROM exam_questions WHERE exam_id = %s", (exam_id,))
    return int(row["n"]) if row else 0


def load_questions(exam_id, legacy_blob=None):
    """Memuat soal dari tabel exam_questions (urut nomor soal).
    Jika belum ada baris (ujian lama), fallback ke blob exams.encrypted_question."""
    rows = execute_query(
        "SELECT * FROM exam_questions WHERE exam_id = %s ORDER BY question_no ASC",
        (exam_id,), fetch=True,
    ) or []

    if rows:
        questions = []
        for r in rows:
            questions.append({
                "question": decrypt_field(r["encrypted_question"]),
                "options": {
                    "A": decrypt_field(r["encrypted_option_a"]),
                    "B": decrypt_field(r["encrypted_option_b"]),
                    "C": decrypt_field(r["encrypted_option_c"]),
                    "D": decrypt_field(r["encrypted_option_d"]),
                },
                "correct": decrypt_field(r["encrypted_answer"]),
            })
        return questions

    if legacy_blob:
        return [normalize_question(q) for q in decrypt_legacy_blob(legacy_blob)]
    return []


def _upsert_statement(exam_id, question_no, q):
    q = normalize_question(q)
    return (
        """
        INSERT INTO exam_questions
            (exam_id, question_no, encrypted_question, encrypted_option_a, encrypted_option_b,
             encrypted_option_c, encrypted_option_d, encrypted_answer)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        ON DUPLICATE KEY UPDATE
            encrypted_question = VALUES(encrypted_question),
            encrypted_option_a = VALUES(encrypted_option_a),
            encrypted_option_b = VALUES(encrypted_option_b),
            encrypted_option_c = VALUES(encrypted_option_c),
            encrypted_option_d = VALUES(encrypted_option_d),
            encrypted_answer   = VALUES(encrypted_answer)
        """,
        (
            exam_id, question_no,
            encrypt_field(q["question"]),
            encrypt_field(q["options"]["A"]),
            encrypt_field(q["options"]["B"]),
            encrypt_field(q["options"]["C"]),
            encrypt_field(q["options"]["D"]),
            encrypt_field(q["correct"]),
        ),
    )


def save_questions(exam_id, questions):
    """Menyimpan seluruh soal sebuah ujian (upsert per soal) dalam satu transaksi.
    Soal yang nomornya melebihi jumlah soal baru akan dihapus."""
    questions = [normalize_question(q) for q in questions]
    statements = [_upsert_statement(exam_id, i + 1, q) for i, q in enumerate(questions)]
    statements.append((
        "DELETE FROM exam_questions WHERE exam_id = %s AND question_no > %s",
        (exam_id, len(questions)),
    ))
    statements.append((
        "UPDATE exams SET encrypted_question = %s, encrypted_answer_key = %s WHERE id = %s",
        (encrypt_legacy_blob(questions), _answer_key_json(questions), exam_id),
    ))
    return run_transaction(statements)


def save_single_question(exam_id, question_no, q):
    """Menyimpan SATU soal (nomor 1-based) lalu menyinkronkan kunci jawaban & blob ujian."""
    if not run_transaction([_upsert_statement(exam_id, question_no, q)]):
        return False
    questions = load_questions(exam_id)
    return run_transaction([(
        "UPDATE exams SET encrypted_question = %s, encrypted_answer_key = %s WHERE id = %s",
        (encrypt_legacy_blob(questions), _answer_key_json(questions), exam_id),
    )])


def migrate_legacy_exams():
    """Memecah blob soal ujian PG lama menjadi baris per soal di exam_questions.
    Hanya memproses ujian PG yang belum punya baris soal. Mengembalikan jumlah ujian yang dimigrasi."""
    legacy = execute_query(
        """
        SELECT e.id, e.encrypted_question FROM exams e
        LEFT JOIN exam_questions q ON q.exam_id = e.id
        WHERE (e.token_hash IS NULL OR e.token_hash <> 'PDF_MODE') AND q.id IS NULL
        """,
        fetch=True,
    ) or []
    migrated = 0
    for ex in legacy:
        try:
            questions = decrypt_legacy_blob(ex["encrypted_question"])
        except Exception as e:
            print(f"[migrasi] Ujian #{ex['id']} gagal didekripsi: {e}")
            continue
        if questions and save_questions(ex["id"], questions):
            migrated += 1
    return migrated
