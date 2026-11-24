"""
Biometrik wajah (OpenCV murni, tanpa dlib).

1. Deteksi wajah: Haar Cascade frontal face.
2. Normalisasi: crop wajah -> grayscale 128x128 -> CLAHE (pemerataan cahaya).
3. Fitur: LBPH (Local Binary Pattern Histogram), grid 8x8, pola uniform (59 bin/sel).
4. Pencocokan: histogram intersection rata-rata (0..1) terhadap semua foto referensi.
5. Template disimpan di database dalam bentuk TERENKRIPSI AES-256-GCM.
Ambang kecocokan dihitung per pengguna dari kemiripan antar foto referensinya sendiri,
dengan batas bawah global, sehingga lebih adil terhadap kondisi kamera masing-masing.

Format template:
  v1 (lama) : JSON berisi daftar angka float (~80 KB per foto) — tetap bisa dibaca.
  v2 (baru) : array float16 dikompres zlib (~10x lebih kecil, aman untuk max_allowed_packet XAMPP).
"""
import base64
import json
import os
import zlib
from datetime import datetime

import cv2
import numpy as np

from modules.crypto_store import aes_decrypt_b64, aes_encrypt_b64
from modules.database import execute_query, get_last_error

FACE_SIZE = 128
GRID = 8
BINS = 59
FEATURE_SHAPE = (GRID * GRID, BINS)
MAX_TEMPLATES = 5
MIN_TEMPLATES = 2
GLOBAL_MIN_THRESHOLD = 0.55   # batas bawah (wajah orang lain umumnya < 0.55)
THRESHOLD_CAP = 0.65          # batas atas agar tidak terlalu ketat
MARGIN = 0.08
MAX_IMAGE_SIDE = 1280         # foto sangat besar (kamera HP) diperkecil dulu agar cepat
PURPOSE = "biometric"

CASCADE_FILE = "haarcascade_frontalface_default.xml"
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class BiometricDataError(Exception):
    """Template biometrik di database tidak bisa dibaca (rusak / master.key berbeda / DB error)."""


# --------------------------------------------------------------------------- cascade
def _cascade_candidates():
    # File cascade dibundel di assets/ karena OpenCV 5 tidak lagi menyertakannya.
    paths = [os.path.join("assets", CASCADE_FILE), os.path.join(BASE_DIR, "assets", CASCADE_FILE)]
    if hasattr(cv2, "data"):
        paths.append(os.path.join(cv2.data.haarcascades, CASCADE_FILE))
    return [p for p in dict.fromkeys(paths) if os.path.exists(p)]


def _load_cascade():
    for path in _cascade_candidates():
        cascade = cv2.CascadeClassifier(path)
        if not cascade.empty():
            return cascade
        # OpenCV di Windows gagal membuka path yang mengandung karakter non-ASCII
        # (mis. nama folder pengguna). Baca isi XML-nya lewat Python lalu muat dari memori.
        try:
            with open(path, encoding="utf-8") as f:
                storage = cv2.FileStorage(f.read(), cv2.FILE_STORAGE_READ | cv2.FILE_STORAGE_MEMORY)
            cascade = cv2.CascadeClassifier()
            if cascade.read(storage.getFirstTopLevelNode()) and not cascade.empty():
                return cascade
        except (OSError, cv2.error):
            continue
    raise RuntimeError("File assets/haarcascade_frontalface_default.xml tidak ditemukan atau tidak bisa dibaca OpenCV.")


_cascade = None


def _get_cascade():
    global _cascade
    if _cascade is None:
        _cascade = _load_cascade()
    return _cascade


# --------------------------------------------------------------------------- LBP
def _uniform_lut():
    lut = np.full(256, BINS - 1, dtype=np.uint8)
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
    if not image_bytes:
        raise ValueError("Foto kosong. Ambil foto ulang.")
    try:
        img = cv2.imdecode(np.frombuffer(image_bytes, dtype=np.uint8), cv2.IMREAD_COLOR)
    except cv2.error:
        img = None
    if img is None:
        raise ValueError("Gambar tidak dapat dibaca. Ambil foto ulang.")
    h, w = img.shape[:2]
    if max(h, w) > MAX_IMAGE_SIDE:
        s = MAX_IMAGE_SIDE / max(h, w)
        img = cv2.resize(img, (int(w * s), int(h * s)), interpolation=cv2.INTER_AREA)
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
    """Crop PERSEGI di sekitar wajah. Gambar diberi tepi (replicate) dulu, sehingga crop di dekat
    tepi frame tidak terpotong lalu tergencet (aspek rusak) saat di-resize ke 128x128."""
    x, y, w, h = box
    cx, cy = x + w / 2 + dx * w, y + h / 2 + dy * h
    half = 0.4 * w * scale  # buang 10% tepi kotak (rambut/latar)
    side = max(8, int(round(2 * half)))
    pad = side + 2
    padded = cv2.copyMakeBorder(gray, pad, pad, pad, pad, cv2.BORDER_REPLICATE)
    x0, y0 = int(round(cx - half)) + pad, int(round(cy - half)) + pad
    face = cv2.resize(padded[y0:y0 + side, x0:x0 + side], (FACE_SIZE, FACE_SIZE), interpolation=cv2.INTER_AREA)
    return cv2.createCLAHE(clipLimit=2.0, tileGridSize=(4, 4)).apply(face)


def detect_face(image_bytes, _return_context=False):
    """(wajah_ternormalisasi 128x128 | None, pesan, gambar_beranotasi_RGB | None).
    Tidak pernah melempar exception untuk gambar yang rusak."""
    try:
        img = _decode(image_bytes)
    except ValueError as e:
        return (None, str(e), None) + ((None, None) if _return_context else ())
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
            hist = np.bincount(cell.ravel(), minlength=BINS).astype(np.float32)
            feats.append(hist / max(hist.sum(), 1))
    return np.stack(feats)  # (64, 59)


def similarity(a, b):
    return float(np.mean(np.minimum(a, b).sum(axis=1)))


# --------------------------------------------------------------------------- penyimpanan
def _pack(templates):
    arr = np.ascontiguousarray(np.stack(templates).astype(np.float16))
    return json.dumps({
        "v": 2, "dtype": "float16", "shape": list(arr.shape),
        "z": base64.b64encode(zlib.compress(arr.tobytes(), 9)).decode(),
    }).encode("utf-8")


def _unpack(raw):
    data = json.loads(raw.decode("utf-8"))
    if data.get("v") == 2:
        shape = tuple(int(v) for v in data["shape"])
        arr = np.frombuffer(zlib.decompress(base64.b64decode(data["z"])), dtype=np.float16).reshape(shape)
        templates = [t.astype(np.float32) for t in arr]
    else:  # v1: JSON daftar angka
        templates = [np.array(t, dtype=np.float32) for t in data["templates"]]
    if any(t.shape != FEATURE_SHAPE for t in templates):
        raise ValueError("ukuran template tidak sesuai")
    return templates


def _load(user_id):
    row = execute_query("SELECT biometric_template FROM users WHERE id = %s", (user_id,))
    if row is None and get_last_error():
        raise BiometricDataError(f"Gagal membaca database: {get_last_error()}")
    if not row or not row.get("biometric_template"):
        return []
    try:
        return _unpack(aes_decrypt_b64(row["biometric_template"], PURPOSE))
    except Exception as e:  # InvalidTag (master.key beda / data diubah), JSON rusak, dll.
        raise BiometricDataError("Template biometrik tidak bisa dibuka (rusak, diubah di database, "
                                 "atau config/master.key berbeda).") from e


def _save(user_id, templates):
    return execute_query(
        "UPDATE users SET biometric_template = %s, biometric_updated_at = %s WHERE id = %s",
        (aes_encrypt_b64(_pack(templates), PURPOSE), datetime.now(), user_id),
    )


def status(user_id):
    """('none' | 'partial' | 'active' | 'corrupt', jumlah_foto, pesan)."""
    try:
        n = len(_load(user_id))
    except BiometricDataError as e:
        return "corrupt", 0, str(e)
    if n >= MIN_TEMPLATES:
        return "active", n, ""
    return ("partial" if n else "none"), n, ""


def template_count(user_id):
    return status(user_id)[1]


def is_enrolled(user_id):
    return status(user_id)[0] == "active"


def user_threshold(templates):
    if len(templates) < 2:
        return GLOBAL_MIN_THRESHOLD
    sims = [similarity(templates[i], templates[j])
            for i in range(len(templates)) for j in range(i + 1, len(templates))]
    return float(min(THRESHOLD_CAP, max(GLOBAL_MIN_THRESHOLD, float(np.mean(sims)) - MARGIN)))


def add_reference(user_id, image_bytes):
    """(ok, pesan). Menambah satu foto referensi (maks 5, yang terlama dibuang)."""
    face, msg, _ = detect_face(image_bytes)
    if face is None:
        return False, msg
    try:
        templates = _load(user_id)
    except BiometricDataError as e:
        return False, f"{e} Hapus data biometrik lama terlebih dahulu, lalu daftarkan ulang."
    feat = lbp_features(face)
    if templates and max(similarity(feat, t) for t in templates) < GLOBAL_MIN_THRESHOLD - 0.05:
        return False, "Foto ini terlalu berbeda dari foto referensi sebelumnya (orang lain?). Ulangi."
    templates = (templates + [feat])[-MAX_TEMPLATES:]
    if not _save(user_id, templates):
        return False, f"Gagal menyimpan template biometrik: {get_last_error() or 'baris pengguna tidak ditemukan'}"
    return True, f"Foto referensi tersimpan ({len(templates)}/{MAX_TEMPLATES}, terenkripsi AES-256-GCM)."


def verify(user_id, image_bytes, with_reason=False):
    """(ok, skor, ambang, pesan[, alasan]). Tidak pernah melempar exception.
    alasan: match | no_match | no_face | bad_image | no_data | corrupt."""
    def out(ok, score, thr, msg, reason):
        return (ok, score, thr, msg, reason) if with_reason else (ok, score, thr, msg)
    try:
        templates = _load(user_id)
    except BiometricDataError as e:
        return out(False, 0.0, GLOBAL_MIN_THRESHOLD, str(e), "corrupt")
    if len(templates) < MIN_TEMPLATES:
        return out(False, 0.0, GLOBAL_MIN_THRESHOLD, "Data biometrik belum lengkap.", "no_data")
    threshold = user_threshold(templates)
    face, msg, annotated, gray, box = detect_face(image_bytes, _return_context=True)
    if face is None:
        return out(False, 0.0, threshold, msg, "bad_image" if annotated is None else "no_face")
    probes = [lbp_features(_normalize(gray, box, dx, dy, scale))
              for dx in (-0.04, 0.0, 0.04) for dy in (-0.04, 0.0, 0.04) for scale in (0.95, 1.0, 1.05)]
    score = max(similarity(p, t) for p in probes for t in templates)
    if score >= threshold:
        return out(True, score, threshold, f"Wajah cocok (skor {score:.3f} ≥ ambang {threshold:.3f}).", "match")
    return out(False, score, threshold, f"Wajah tidak cocok (skor {score:.3f} < ambang {threshold:.3f}).", "no_match")


def clear(user_id):
    return execute_query(
        "UPDATE users SET biometric_template = NULL, biometric_updated_at = NULL WHERE id = %s",
        (user_id,),
    )
