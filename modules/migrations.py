"""Migrasi data lama agar seluruh data penting di database terenkripsi. Aman dijalankan berulang."""
import json

from modules.crypto_store import is_hashed, is_super_encrypted, super_encrypt
from modules.database import execute_query, get_meta, set_meta
from modules.exam_access import text_token_columns
from modules.integrity import _current_assets, ledger_index, record
from modules.modern_cipher import aes_decrypt
from modules.question_bank import AES_KEY, _answer_key_json, migrate_legacy_exams, load_questions


def run_migrations(blockchain):
    changed = set()
    for exam_id in migrate_legacy_exams_ids():
        changed.add(("exam", exam_id))

    # 1) Token teks PG plaintext -> hash PBKDF2 + salinan super-enkripsi
    for ex in execute_query("SELECT id, token_hash FROM exams WHERE token_hash IS NOT NULL", fetch=True) or []:
        if ex["token_hash"] != "PDF_MODE" and not is_hashed(ex["token_hash"]):
            token_hash, token_enc = text_token_columns(ex["token_hash"])
            execute_query("UPDATE exams SET token_hash=%s, token_encrypted=%s WHERE id=%s",
                          (token_hash, token_enc, ex["id"]))
            changed.add(("exam", ex["id"]))

    # 2) Kunci jawaban JSON polos -> super-enkripsi
    for ex in execute_query("SELECT id, token_hash, encrypted_answer_key FROM exams", fetch=True) or []:
        if ex["token_hash"] != "PDF_MODE" and not is_super_encrypted(ex["encrypted_answer_key"]):
            questions = load_questions(ex["id"])
            execute_query("UPDATE exams SET encrypted_answer_key=%s WHERE id=%s",
                          (_answer_key_json(questions), ex["id"]))
            changed.add(("exam", ex["id"]))

    # 3) Kunci file PDF polos -> super-enkripsi
    for rec in execute_query("SELECT id, exam_id, file_key FROM exam_files WHERE file_key IS NOT NULL", fetch=True) or []:
        if not is_super_encrypted(rec["file_key"]):
            execute_query("UPDATE exam_files SET file_key=%s WHERE id=%s",
                          (super_encrypt(rec["file_key"], "pdf-key"), rec["id"]))
            changed.add(("exam_file", rec["exam_id"]))

    # 4) Jawaban mahasiswa AES-only -> super-enkripsi (Vigenère + AES)
    for sub in execute_query("SELECT id, encrypted_answers FROM student_submissions", fetch=True) or []:
        if not is_super_encrypted(sub["encrypted_answers"]):
            plain = aes_decrypt(sub["encrypted_answers"], AES_KEY)
            if plain.startswith("[Error"):
                continue
            execute_query("UPDATE student_submissions SET encrypted_answers=%s WHERE id=%s",
                          (super_encrypt(plain, "answers"), sub["id"]))
            changed.add(("submission", sub["id"]))

    for kind, asset_id in sorted(changed):
        record(blockchain, "MIGRATE_ENCRYPT", kind, asset_id)

    # 5) Baseline satu kali: aset lama yang belum pernah tercatat di blockchain
    if not get_meta("asset_baseline_v1"):
        ledger = ledger_index()
        for kind, asset_id, _ in _current_assets():
            if f"{kind}:{asset_id}" not in ledger:
                record(blockchain, "BASELINE_ASSET", kind, asset_id)
        set_meta("asset_baseline_v1", "done")
    return changed


def migrate_legacy_exams_ids():
    before = {r["exam_id"] for r in execute_query("SELECT DISTINCT exam_id FROM exam_questions", fetch=True) or []}
    migrate_legacy_exams()
    after = {r["exam_id"] for r in execute_query("SELECT DISTINCT exam_id FROM exam_questions", fetch=True) or []}
    return after - before
