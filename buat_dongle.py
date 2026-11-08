"""
Pembuat FLASHDISK DONGLE untuk SRIKANDI.

Cara pakai (colokkan flashdisk terlebih dahulu):
    python buat_dongle.py                 -> pilih flashdisk dari daftar
    python buat_dongle.py --drive E:\\     -> langsung ke drive E:
    python buat_dongle.py --dev           -> dongle virtual (hanya jika SRIKANDI_DEV_MODE=1)

Pertama kali dijalankan, skrip membuat pasangan kunci Ed25519:
    dongle_admin/dongle_private.pem  -> KUNCI PRIVAT (simpan baik-baik, jangan dibagikan)
    config/dongle_public.pem         -> kunci publik yang dipakai aplikasi
Isi dongle.key = tanda tangan Ed25519 atas nomor seri volume flashdisk.
"""
import argparse
import base64
import json
import os
import socket
import sys
from datetime import datetime

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

HERE = os.path.dirname(os.path.abspath(__file__))
os.chdir(HERE)                 # agar folder config/ selalu milik proyek ini
sys.path.insert(0, HERE)

from modules.auth import (
    DEV_DONGLE_PATH, DEV_SERIAL, DONGLE_FILENAME, PUBLIC_KEY_PATH,
    candidate_roots, check_dongle, dongle_message, volume_serial,
)

PRIVATE_KEY_PATH = os.path.join("dongle_admin", "dongle_private.pem")


def load_or_create_private_key():
    if os.path.exists(PRIVATE_KEY_PATH):
        with open(PRIVATE_KEY_PATH, "rb") as f:
            return serialization.load_pem_private_key(f.read(), password=None)
    if os.path.exists(PUBLIC_KEY_PATH):
        print("⚠️  config/dongle_public.pem sudah ada tetapi kunci privatnya tidak ditemukan.")
        if input("Buat pasangan kunci BARU? Semua dongle lama jadi tidak berlaku. (y/N): ").strip().lower() != "y":
            sys.exit(1)
    key = Ed25519PrivateKey.generate()
    os.makedirs("dongle_admin", exist_ok=True)
    os.makedirs("config", exist_ok=True)
    with open(PRIVATE_KEY_PATH, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption()))
    with open(PUBLIC_KEY_PATH, "wb") as f:
        f.write(key.public_key().public_bytes(serialization.Encoding.PEM,
                                              serialization.PublicFormat.SubjectPublicKeyInfo))
    print(f"🔑 Pasangan kunci Ed25519 dibuat: {PRIVATE_KEY_PATH} & {PUBLIC_KEY_PATH}")
    return key


def write_dongle(private_key, target_path, serial, owner):
    data = {
        "product": "SRIKANDI Secure Exam",
        "version": 1,
        "serial": serial,
        "owner": owner,
        "issued_at": datetime.now().isoformat(timespec="seconds"),
        "signature": base64.b64encode(private_key.sign(dongle_message(serial))).decode(),
    }
    with open(target_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def main():
    parser = argparse.ArgumentParser(description="Buat flashdisk dongle SRIKANDI")
    parser.add_argument("--drive", help="Root flashdisk, mis. E:\\")
    parser.add_argument("--owner", default=socket.gethostname(), help="Nama pemilik dongle")
    parser.add_argument("--dev", action="store_true", help="Buat dongle virtual untuk pengembangan")
    args = parser.parse_args()

    private_key = load_or_create_private_key()

    if args.dev:
        write_dongle(private_key, DEV_DONGLE_PATH, DEV_SERIAL, args.owner + " (DEV)")
        print(f"✅ Dongle virtual dibuat: {DEV_DONGLE_PATH}. Aktif hanya jika env SRIKANDI_DEV_MODE=1")
        return

    root = args.drive
    if not root:
        roots = [r for r in candidate_roots() if volume_serial(r)]
        if not roots:
            print("❌ Tidak ada flashdisk terdeteksi. Colokkan flashdisk lalu ulangi.")
            sys.exit(1)
        for i, r in enumerate(roots, 1):
            print(f"  [{i}] {r}  (serial {volume_serial(r)})")
        choice = input("Pilih nomor flashdisk: ").strip()
        root = roots[int(choice) - 1]

    serial = volume_serial(root)
    if not serial:
        print(f"❌ Tidak bisa membaca nomor seri volume {root}")
        sys.exit(1)
    write_dongle(private_key, os.path.join(root, DONGLE_FILENAME), serial, args.owner)
    print(f"✅ Dongle ditulis ke {os.path.join(root, DONGLE_FILENAME)} (serial {serial})")
    ok, msg = check_dongle()
    print(("✅ " if ok else "❌ ") + msg)


if __name__ == "__main__":
    main()
