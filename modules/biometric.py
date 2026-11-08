"""
Biometrik wajah (OpenCV murni, tanpa dlib).

1. Deteksi wajah: Haar Cascade frontal face.
2. Normalisasi: crop wajah terbesar -> grayscale 128x128 -> CLAHE (pemerataan cahaya).
3. Fitur: LBPH (Local Binary Pattern Histogram), grid 8x8, pola uniform (59 bin/sel).
4. Pencocokan: histogram intersection rata-rata (0..1) terhadap semua foto referensi.
5. Template disimpan di database dalam bentuk TERENKRIPSI AES-256-GCM.
Ambang kecocokan dihitung per pengguna dari kemiripan antar foto referensinya sendiri,
dengan batas bawah global, sehingga lebih adil terhadap kondisi kamera masing-masing.
"""
import json
import os
from datetime import datetime

import cv2
import numpy as np

from modules.crypto_store import aes_decrypt_b64, aes_encrypt_b64
from modules.database import execute_query

FACE_SIZE = 128
GRID = 8
MAX_TEMPLATES = 5
MIN_TEMPLATES = 2
GLOBAL_MIN_THRESHOLD = 0.55   # batas bawah (wajah orang lain umumnya < 0.55)
THRESHOLD_CAP = 0.65          # batas atas agar tidak terlalu ketat
MARGIN = 0.08
PURPOSE = "biometric"

CASCADE_FILE = "haarcascade_frontalface_default.xml"


def _load_cascade():
    # File cascade dibundel di assets/ karena OpenCV 5 tidak lagi menyertakannya.
    candidates = [os.path.join("assets", CASCADE_FILE)]
    if hasattr(cv2, "data"):
        candidates.append(os.path.join(cv2.data.haarcascades, CASCADE_FILE))
    for path in candidates:
        if os.path.exists(path):
            cascade = cv2.CascadeClassifier(path)
            if not cascade.empty():
                return cascade
    raise RuntimeError("File haarcascade_frontalface_default.xml tidak ditemukan / OpenCV tidak mendukung.")


_cascade = None


def _get_cascade():
    global _cascade
    if _cascade is None:
        _cascade = _load_cascade()
    return _cascade


def _uniform_lut():
    lut = np.full(256, 58, dtype=np.uint8)
    idx = 0
    for code in range(256):
        bits = [(code >> i) & 1 for i in range(8)]
        transitions = sum(bits[i] != bits[(i + 1) % 8] for i in range(8))
        if transitions <= 2:
            lut[code] = idx
            idx += 1
    return lut


_LUT = _uniform_lut()


def _decode(image_bytes):
    arr = np.frombuffer(image_bytes, dtype=np.uint8)
    img = cv2.imdecode(arr, cv2.IMREAD_COLOR)
    if img is None:
        raise ValueError("Gambar tidak dapat dibaca.")
    return img


def _find_face(gray):
    """Kotak wajah paling meyakinkan: dipilih berdasarkan jumlah deteksi tetangga terbanyak
    (bukan kotak terbesar, karena false positive sering berukuran besar)."""
    min_side = max(60, min(gray.shape) // 6)
    boxes, neighbors = _get_cascade().detectMultiScale2(
        gray, scaleFactor=1.1, minNeighbors=5, minSize=(min_side, min_side))
    if len(boxes) == 0:
        return None, 0
    best = int(np.argmax(np.asarray(neighbors).reshape(-1)))
    return tuple(int(v) for v in boxes[best]), len(boxes)


def _normalize(gray, box, dx=0, dy=0, scale=1.0):
    x, y, w, h = box
    cx, cy = x + w / 2 + dx * w, y + h / 2 + dy * h
    half = 0.4 * w * scale  # buang 10% tepi kotak (rambut/latar)
    x0, y0 = int(max(0, cx - half)), int(max(0, cy - half))
    x1, y1 = int(min(gray.shape[1], cx + half)), int(min(gray.shape[0], cy + half))
    face = cv2.resize(gray[y0:y1, x0:x1], (FACE_SIZE, FACE_SIZE), interpolation=cv2.INTER_AREA)
    return cv2.createCLAHE(clipLimit=2.0, tileGridSize=(4, 4)).apply(face)


def detect_face(image_bytes, _return_context=False):
    """(wajah_ternormalisasi 128x128 | None, pesan, gambar_beranotasi_RGB)."""
    img = _decode(image_bytes)
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    annotated = cv2.cvtColor(img, cv2.COLOR_BGR2RGB)
    box, n = _find_face(gray)
    if box is None:
        return (None, "Wajah tidak terdeteksi. Hadapkan wajah ke kamera dengan pencahayaan cukup.", annotated) + \
            ((None, None) if _return_context else ())
    x, y, w, h = box
    cv2.rectangle(annotated, (x, y), (x + w, y + h), (26, 127, 90), 3)
    note = "Wajah terdeteksi." if n == 1 else "Beberapa kandidat wajah; yang paling meyakinkan dipakai."
    result = (_normalize(gray, box), note, annotated)
    return result + ((gray, box) if _return_context else ())


def _probe_features(image_bytes):
    """Fitur wajah pada beberapa pergeseran/skala kecil (tahan terhadap crop yang meleset)."""
    face, msg, _, gray, box = detect_face(image_bytes, _return_context=True)
    if face is None:
        return None, msg
    feats = []
    for dx in (-0.04, 0.0, 0.04):
        for dy in (-0.04, 0.0, 0.04):
            for scale in (0.95, 1.0, 1.05):
                feats.append(lbp_features(_normalize(gray, box, dx, dy, scale)))
    return feats, msg


def lbp_features(face):
    f = face.astype(np.int16)
    c = f[1:-1, 1:-1]
    neighbors = [f[:-2, :-2], f[:-2, 1:-1], f[:-2, 2:], f[1:-1, 2:],
                 f[2:, 2:], f[2:, 1:-1], f[2:, :-2], f[1:-1, :-2]]
    code = np.zeros(c.shape, dtype=np.uint8)
    for i, n in enumerate(neighbors):
        code |= ((n >= c).astype(np.uint8) << i)
    mapped = _LUT[code]
    h, w = mapped.shape
    feats = []
    for gy in range(GRID):
        for gx in range(GRID):
            cell = mapped[gy * h // GRID:(gy + 1) * h // GRID, gx * w // GRID:(gx + 1) * w // GRID]
            hist = np.bincount(cell.ravel(), minlength=59).astype(np.float32)
            feats.append(hist / max(hist.sum(), 1))
    return np.stack(feats)  # (64, 59)


def similarity(a, b):
    return float(np.mean(np.minimum(a, b).sum(axis=1)))


def _load(user_id):
    row = execute_query("SELECT biometric_template, biometric_updated_at FROM users WHERE id = %s", (user_id,))
    if not row or not row.get("biometric_template"):
        return []
    data = json.loads(aes_decrypt_b64(row["biometric_template"], PURPOSE).decode("utf-8"))
    return [np.array(t, dtype=np.float32) for t in data["templates"]]


def _save(user_id, templates):
    payload = json.dumps({"v": 1, "templates": [np.round(t, 5).tolist() for t in templates]}).encode("utf-8")
    return execute_query(
        "UPDATE users SET biometric_template = %s, biometric_updated_at = %s WHERE id = %s",
        (aes_encrypt_b64(payload, PURPOSE), datetime.now(), user_id),
    )


def template_count(user_id):
    try:
        return len(_load(user_id))
    except Exception:
        return 0


def is_enrolled(user_id):
    return template_count(user_id) >= MIN_TEMPLATES


def user_threshold(templates):
    if len(templates) < 2:
        return GLOBAL_MIN_THRESHOLD
    sims = [similarity(templates[i], templates[j])
            for i in range(len(templates)) for j in range(i + 1, len(templates))]
    return float(min(THRESHOLD_CAP, max(GLOBAL_MIN_THRESHOLD, float(np.mean(sims)) - MARGIN)))


def add_reference(user_id, image_bytes):
    """(ok, pesan). Menambah satu foto referensi (maks 5)."""
    face, msg, _ = detect_face(image_bytes)
    if face is None:
        return False, msg
    templates = _load(user_id)
    feat = lbp_features(face)
    if templates and max(similarity(feat, t) for t in templates) < GLOBAL_MIN_THRESHOLD - 0.05:
        return False, "Foto ini terlalu berbeda dari foto referensi sebelumnya (orang lain?). Ulangi."
    templates = (templates + [feat])[-MAX_TEMPLATES:]
    if _save(user_id, templates) is None:
        return False, "Gagal menyimpan template biometrik."
    return True, f"Foto referensi ke-{len(templates)} tersimpan (terenkripsi AES-256-GCM)."


def verify(user_id, image_bytes):
    """(ok, skor, ambang, pesan)."""
    templates = _load(user_id)
    if len(templates) < MIN_TEMPLATES:
        return False, 0.0, GLOBAL_MIN_THRESHOLD, "Data biometrik belum lengkap."
    probes, msg = _probe_features(image_bytes)
    if probes is None:
        return False, 0.0, user_threshold(templates), msg
    score = max(similarity(p, t) for p in probes for t in templates)
    threshold = user_threshold(templates)
    if score >= threshold:
        return True, score, threshold, f"Wajah cocok (skor {score:.3f} ≥ ambang {threshold:.3f})."
    return False, score, threshold, f"Wajah tidak cocok (skor {score:.3f} < ambang {threshold:.3f})."


def clear(user_id):
    return execute_query(
        "UPDATE users SET biometric_template = NULL, biometric_updated_at = NULL, biometric_path = NULL WHERE id = %s",
        (user_id,),
    )
