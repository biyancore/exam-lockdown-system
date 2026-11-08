"""
Pengamanan ASET PENTING dengan blockchain.

Setiap kali aset dibuat/diubah lewat aplikasi, sidik jari SHA-256-nya dicatat
di blok baru ({"asset": "exam:5", "asset_hash": "..."}). Audit membandingkan
hash aset saat ini di database dengan hash terakhir yang tercatat di rantai.
Jika seseorang mengubah data langsung di phpMyAdmin (misal menaikkan nilai),
hash tidak cocok -> terdeteksi sebagai manipulasi.
"""
import json

from modules.crypto_store import sha256_hex
from modules.database import execute_query

ASSET_LABEL = {
    "exam": "Ujian & bank soal",
    "exam_file": "File PDF terenkripsi",
    "stego": "Gambar token steganografi",
    "submission": "Jawaban & nilai mahasiswa",
    "biometric": "Template biometrik wajah",
}


def _join(parts):
    return sha256_hex("|".join("" if p is None else str(p) for p in parts))


def asset_hash(kind, asset_id):
    if kind == "exam":
        ex = execute_query("SELECT * FROM exams WHERE id = %s", (asset_id,))
        if not ex:
            return None
        qs = execute_query(
            "SELECT * FROM exam_questions WHERE exam_id = %s ORDER BY question_no", (asset_id,), fetch=True
        ) or []
        parts = [ex["exam_code"], ex["title"], ex["duration_minutes"], ex["token_hash"], ex.get("token_mode"),
                 ex.get("token_valid_from"), ex.get("token_valid_until"), ex["encrypted_answer_key"]]
        for q in qs:
            parts += [q["question_no"], q["encrypted_question"], q["encrypted_option_a"], q["encrypted_option_b"],
                      q["encrypted_option_c"], q["encrypted_option_d"], q["encrypted_answer"]]
        return _join(parts)
    if kind == "exam_file":
        rec = execute_query("SELECT * FROM exam_files WHERE exam_id = %s ORDER BY id DESC LIMIT 1", (asset_id,))
        return _join([rec["encrypted_file"], rec.get("file_sha256")]) if rec and rec.get("encrypted_file") else None
    if kind == "stego":
        row = execute_query("SELECT * FROM exam_stego_tokens WHERE id = %s", (asset_id,))
        return _join([row["token_uid"], row["exam_id"], row["stego_sha256"], row["secret_hash"],
                      row["is_active"]]) if row else None
    if kind == "submission":
        row = execute_query("SELECT * FROM student_submissions WHERE id = %s", (asset_id,))
        if not row:
            return None
        score = f"{float(row['score']):.2f}" if row["score"] is not None else ""
        return _join([row["user_id"], row["exam_id"], row["encrypted_answers"], score])
    if kind == "biometric":
        row = execute_query("SELECT biometric_template FROM users WHERE id = %s", (asset_id,))
        return sha256_hex(row["biometric_template"]) if row and row.get("biometric_template") else None
    raise ValueError(kind)


def record(blockchain, event, kind, asset_id, **extra):
    """Tambah blok berisi event + sidik jari aset terkini."""
    data = {"event": event, **extra, "asset": f"{kind}:{asset_id}", "asset_hash": asset_hash(kind, asset_id)}
    return blockchain.add_block(data)


def _current_assets():
    assets = []
    for ex in execute_query("SELECT id, exam_code, title, token_hash FROM exams", fetch=True) or []:
        assets.append(("exam", ex["id"], f"{ex['exam_code']} — {ex['title']}"))
        if ex["token_hash"] == "PDF_MODE":
            assets.append(("exam_file", ex["id"], f"File PDF {ex['exam_code']}"))
    for t in execute_query("SELECT id, label, exam_id FROM exam_stego_tokens", fetch=True) or []:
        assets.append(("stego", t["id"], f"{t['label']} (ujian #{t['exam_id']})"))
    for s in execute_query(
        "SELECT s.id, u.username, e.exam_code FROM student_submissions s "
        "LEFT JOIN users u ON u.id = s.user_id LEFT JOIN exams e ON e.id = s.exam_id", fetch=True
    ) or []:
        assets.append(("submission", s["id"], f"{s['username']} · {s['exam_code']}"))
    for u in execute_query("SELECT id, username FROM users WHERE biometric_template IS NOT NULL", fetch=True) or []:
        assets.append(("biometric", u["id"], f"Wajah {u['username']}"))
    return assets


def ledger_index():
    """asset_key -> data blok terakhir yang mencatat aset tersebut."""
    index = {}
    for block in execute_query(
        "SELECT block_index, timestamp, data_payload FROM blockchain_logs ORDER BY block_index", fetch=True
    ) or []:
        try:
            data = json.loads(block["data_payload"])
        except (TypeError, ValueError):
            continue
        if isinstance(data, dict) and data.get("asset"):
            index[data["asset"]] = {"block": block["block_index"], "time": block["timestamp"],
                                    "event": data.get("event"), "hash": data.get("asset_hash")}
    return index


def audit():
    """Daftar hasil audit: status 'valid' | 'tampered' | 'unrecorded'."""
    ledger = ledger_index()
    results = []
    for kind, asset_id, label in _current_assets():
        key = f"{kind}:{asset_id}"
        current = asset_hash(kind, asset_id)
        rec = ledger.get(key)
        if current is None:
            continue
        if not rec or rec["hash"] is None:
            status = "unrecorded"
        elif rec["hash"] == current:
            status = "valid"
        else:
            status = "tampered"
        results.append({"key": key, "kind": kind, "id": asset_id, "label": label, "status": status,
                        "current": current, "recorded": rec["hash"] if rec else None,
                        "block": rec["block"] if rec else None, "event": rec["event"] if rec else None})
    return results


def check_asset(kind, asset_id):
    """'valid' | 'tampered' | 'unrecorded' untuk satu aset."""
    rec = ledger_index().get(f"{kind}:{asset_id}")
    if not rec or rec["hash"] is None:
        return "unrecorded"
    return "valid" if rec["hash"] == asset_hash(kind, asset_id) else "tampered"
