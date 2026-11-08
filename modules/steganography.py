"""
Steganografi LSB (Least Significant Bit) pada gambar RGB.

Format data yang disisipkan (bit demi bit ke LSB kanal R, G, B secara berurutan):
    MAGIC "SRKS" (4 byte) | panjang payload (4 byte, big-endian) | payload

Perubahan maksimal tiap kanal warna hanya ±1 (dari 0-255), sehingga secara
kasat mata gambar terlihat sama, tetapi isinya berbeda (hash SHA-256 berbeda).
Simpan / bagikan selalu sebagai PNG: JPEG (lossy) akan merusak bit LSB.
"""
import io

import numpy as np
from PIL import Image

MAGIC = b"SRKS"
HEADER_BYTES = 8
MAX_COVER_SIDE = 1600


def load_rgb(source):
    """Membuka gambar dari bytes / file-like / path dan mengubahnya ke RGB."""
    if isinstance(source, (bytes, bytearray)):
        source = io.BytesIO(source)
    img = Image.open(source)
    img.load()
    if img.mode == "RGBA":  # tempel di latar putih agar transparansi tidak jadi hitam
        bg = Image.new("RGB", img.size, (255, 255, 255))
        bg.paste(img, mask=img.split()[3])
        return bg
    return img.convert("RGB")


def prepare_cover(img, max_side=MAX_COVER_SIDE):
    """Perkecil gambar sampul yang terlalu besar (hemat ruang database)."""
    if max(img.size) > max_side:
        img = img.copy()
        img.thumbnail((max_side, max_side), Image.LANCZOS)
    return img


def capacity_bits(img):
    w, h = img.size
    return w * h * 3


def capacity_bytes(img):
    return capacity_bits(img) // 8 - HEADER_BYTES


def embed_bytes(img, payload):
    arr = np.array(img.convert("RGB"), dtype=np.uint8)
    flat = arr.reshape(-1).copy()
    data = MAGIC + len(payload).to_bytes(4, "big") + payload
    bits = np.unpackbits(np.frombuffer(data, dtype=np.uint8))
    if bits.size > flat.size:
        raise ValueError(
            f"Gambar terlalu kecil: butuh {bits.size:,} bit, kapasitas {flat.size:,} bit.".replace(",", ".")
        )
    flat[:bits.size] = (flat[:bits.size] & 0xFE) | bits
    return Image.fromarray(flat.reshape(arr.shape), "RGB")


def extract_bytes(img):
    """Mengembalikan payload, atau None jika gambar tidak berisi data SRIKANDI."""
    flat = np.array(img.convert("RGB"), dtype=np.uint8).reshape(-1)
    if flat.size < HEADER_BYTES * 8:
        return None
    header = np.packbits(flat[:HEADER_BYTES * 8] & 1).tobytes()
    if header[:4] != MAGIC:
        return None
    length = int.from_bytes(header[4:8], "big")
    end = (HEADER_BYTES + length) * 8
    if length <= 0 or end > flat.size:
        return None
    return np.packbits(flat[HEADER_BYTES * 8:end] & 1).tobytes()


def payload_bits(payload_len):
    return (HEADER_BYTES + payload_len) * 8


def to_png_bytes(img):
    buf = io.BytesIO()
    img.save(buf, format="PNG", optimize=True)
    return buf.getvalue()


def image_metrics(cover, stego):
    a = np.array(cover.convert("RGB"), dtype=np.int16)
    b = np.array(stego.convert("RGB"), dtype=np.int16)
    diff = np.abs(a - b)
    mse = float(np.mean(diff.astype(np.float64) ** 2))
    psnr = float("inf") if mse == 0 else 10 * np.log10(255 ** 2 / mse)
    return {
        "mse": mse,
        "psnr": psnr,
        "changed_values": int(np.count_nonzero(diff)),
        "changed_pixels": int(np.count_nonzero(diff.any(axis=2))),
        "max_diff": int(diff.max()) if diff.size else 0,
    }


def lsb_plane(img):
    """Visualisasi bidang bit LSB (0 -> hitam, 1 -> putih)."""
    arr = np.array(img.convert("RGB"), dtype=np.uint8)
    return Image.fromarray(((arr & 1) * 255).astype(np.uint8), "RGB")


def diff_map(cover, stego):
    """Piksel yang berubah ditandai merah terang (perbedaan diperkuat agar terlihat)."""
    a = np.array(cover.convert("RGB"), dtype=np.int16)
    b = np.array(stego.convert("RGB"), dtype=np.int16)
    changed = np.any(a != b, axis=2)
    base = (np.array(cover.convert("L"), dtype=np.uint8) // 3).astype(np.uint8)
    out = np.stack([base, base, base], axis=2)
    out[changed] = [255, 40, 40]
    return Image.fromarray(out, "RGB")


# ---------------------------------------------------------------------------
# API lama (berbasis path & teks) — dipertahankan agar kompatibel
# ---------------------------------------------------------------------------
def encode_image(image_path, secret_message, output_path):
    try:
        stego = embed_bytes(load_rgb(image_path), secret_message.encode("utf-8"))
        stego.save(output_path, format="PNG")
        return True, f"Berhasil menyembunyikan token ke {output_path}"
    except Exception as e:
        return False, f"Error steganografi encode: {e}"


def decode_image(image_path):
    try:
        data = extract_bytes(load_rgb(image_path))
        if data is None:
            return False, "Token ujian tidak ditemukan di dalam gambar ini."
        return True, data.decode("utf-8")
    except Exception as e:
        return False, f"Error steganografi decode: {e}"
