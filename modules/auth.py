"""
Autentikasi SRIKANDI.

- Password  : PBKDF2-HMAC-SHA256 (100.000 iterasi) + salt acak 16 byte.
- Dongle    : file dongle.key di flashdisk berisi TANDA TANGAN DIGITAL Ed25519 atas
              nomor seri volume flashdisk tersebut. Aplikasi hanya menyimpan KUNCI
              PUBLIK (config/dongle_public.pem), jadi dongle tidak bisa dipalsukan, dan
              file yang disalin ke flashdisk / folder lain otomatis ditolak (serial beda).
              Dongle dibuat dengan: python buat_dongle.py
- Biometrik : lihat modules/biometric.py
"""
import base64
import binascii
import hashlib
import hmac
import json
import os
import string
import sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization

DONGLE_FILENAME = "dongle.key"
PUBLIC_KEY_PATH = os.path.join("config", "dongle_public.pem")
DEV_DONGLE_PATH = os.path.join("config", "dongle_dev.key")
DEV_SERIAL = "DEV-MODE"


# =========================================================================== DONGLE
def dongle_message(serial):
    return f"SRIKANDI-DONGLE|v1|{serial}".encode("utf-8")


def volume_serial(root):
    """Nomor seri volume (Windows) — unik per partisi flashdisk."""
    if sys.platform.startswith("win"):
        import ctypes
        serial = ctypes.c_uint32()
        ok = ctypes.windll.kernel32.GetVolumeInformationW(
            ctypes.c_wchar_p(root), None, 0, ctypes.byref(serial), None, None, None, 0
        )
        return f"{serial.value:08X}" if ok else None
    try:  # macOS / Linux: gunakan ID perangkat mount point
        return f"DEV{os.stat(root).st_dev:X}"
    except OSError:
        return None


def candidate_roots():
    roots = []
    if sys.platform.startswith("win"):
        import ctypes
        kernel32 = ctypes.windll.kernel32
        kernel32.SetErrorMode(0x0001 | 0x8000)  # jangan munculkan dialog "No disk in drive"
        system_drive = os.environ.get("SystemDrive", "C:").upper()[:1]
        mask = kernel32.GetLogicalDrives()
        for i, letter in enumerate(string.ascii_uppercase):
            root = f"{letter}:\\"
            if not (mask >> i) & 1 or letter in ("A", "B", system_drive):
                continue
            if kernel32.GetDriveTypeW(ctypes.c_wchar_p(root)) in (2, 3):  # REMOVABLE / FIXED (USB HDD)
                roots.append(root)
    else:
        for base in ("/Volumes", "/media", "/run/media", "/mnt"):
            if os.path.isdir(base):
                for name in os.listdir(base):
                    path = os.path.join(base, name)
                    roots.append(path)
                    if os.path.isdir(path) and base != "/Volumes":
                        roots += [os.path.join(path, sub) for sub in os.listdir(path)]
    extra = os.environ.get("SRIKANDI_DONGLE_PATHS")
    if extra:
        roots = extra.split(os.pathsep) + roots
    return roots


def load_public_key():
    if not os.path.exists(PUBLIC_KEY_PATH):
        return None
    with open(PUBLIC_KEY_PATH, "rb") as f:
        return serialization.load_pem_public_key(f.read())


def verify_dongle_file(path, serial, public_key):
    """(ok, data|alasan)."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return False, "isi dongle.key tidak valid"
    if data.get("serial") != serial:
        return False, "dongle.key disalin dari flashdisk lain (nomor seri tidak cocok)"
    try:
        public_key.verify(base64.b64decode(data.get("signature", "")), dongle_message(serial))
    except (InvalidSignature, ValueError, binascii.Error):
        return False, "tanda tangan dongle palsu"
    return True, data


def check_dongle():
    """(ok, pesan). Dipanggil setiap rerun — mencabut flashdisk langsung mengunci aplikasi."""
    public_key = load_public_key()
    if public_key is None:
        return False, ("Kunci publik dongle (config/dongle_public.pem) belum ada. "
                       "Colokkan flashdisk lalu jalankan: python buat_dongle.py")

    reasons = []
    for root in candidate_roots():
        path = os.path.join(root, DONGLE_FILENAME)
        if not os.path.isfile(path):
            continue
        ok, info = verify_dongle_file(path, volume_serial(root), public_key)
        if ok:
            owner = info.get("owner", "-")
            return True, f"Dongle terverifikasi di {root} (Ed25519 · serial {info['serial']} · {owner})"
        reasons.append(f"{root}: {info}")

    if os.environ.get("SRIKANDI_DEV_MODE") == "1" and os.path.isfile(DEV_DONGLE_PATH):
        ok, info = verify_dongle_file(DEV_DONGLE_PATH, DEV_SERIAL, public_key)
        if ok:
            return True, "MODE PENGEMBANGAN — dongle virtual (jangan dipakai saat demo/penilaian)"
        reasons.append(f"dongle dev: {info}")

    detail = (" Ditemukan tetapi ditolak → " + "; ".join(reasons)) if reasons else ""
    return False, "Flashdisk dongle tidak ditemukan! Colokkan flashdisk dongle Anda." + detail


# =========================================================================== PASSWORD
def hash_password(password):
    """Membuat hash password dengan PBKDF2-SHA256 + Salt."""
    salt = os.urandom(16)
    pwd_hash = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100000)
    return binascii.hexlify(salt).decode("utf-8") + ":" + binascii.hexlify(pwd_hash).decode("utf-8")


def verify_password(stored_password, provided_password):
    """Memverifikasi password pengguna (perbandingan waktu-konstan)."""
    try:
        salt_hex, pwd_hash_hex = stored_password.split(":")
        salt = binascii.unhexlify(salt_hex)
        stored_hash = binascii.unhexlify(pwd_hash_hex)
        new_hash = hashlib.pbkdf2_hmac("sha256", provided_password.encode("utf-8"), salt, 100000)
        return hmac.compare_digest(new_hash, stored_hash)
    except Exception:
        return False
