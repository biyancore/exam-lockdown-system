# SRIKANDI — Secure Exam System

Aplikasi ujian daring (Streamlit + MySQL/MariaDB XAMPP) yang menerapkan kriptografi klasik, modern,
steganografi, biometrik, dongle, dan blockchain sederhana.

## 1. Instalasi

```bash
python -m pip install -r requirements.txt
```

1. Jalankan **MySQL** di XAMPP, buat database `secure_exam_db`, lalu impor `secure_exam_db.sql`
   (cukup sekali; kalau database sudah ada, aplikasi akan memperbarui strukturnya sendiri).
2. Akun uji: `python seed_user.py` → `dosen_kripto` / `biyan_mahasiswa`, password `password123`.

## 2. Membuat flashdisk dongle (WAJIB — tanpa ini aplikasi terkunci)

Colokkan flashdisk, lalu di folder proyek jalankan:

```bash
python buat_dongle.py
```

Pilih nomor flashdisk. Skrip akan membuat:

| File | Fungsi |
|---|---|
| `dongle_admin/dongle_private.pem` | **Kunci privat** penanda tangan dongle. Simpan baik-baik, jangan dibagikan. |
| `config/dongle_public.pem` | Kunci publik yang dipakai aplikasi untuk memverifikasi dongle. |
| `<flashdisk>:\dongle.key` | Tanda tangan Ed25519 atas **nomor seri volume** flashdisk tersebut. |

Untuk flashdisk tambahan (anggota tim), jalankan lagi `python buat_dongle.py` di laptop yang memiliki
kunci privat. File `dongle.key` yang disalin ke flashdisk lain **ditolak**, karena nomor serinya berbeda.

> Mode pengembangan (tanpa flashdisk, **jangan dipakai saat penilaian**):
> `python buat_dongle.py --dev`, lalu jalankan aplikasi dengan variabel lingkungan `SRIKANDI_DEV_MODE=1`.

## 3. Menjalankan

```bash
python -m streamlit run app.py
```

Login pertama cukup dengan password. Daftarkan wajah di menu **👤 Profil** (minimal 2 foto). Setelah itu
login **wajib** melewati verifikasi wajah.

> ⚠️ **Simpan folder `config/`** (`master.key`, `session.key`, `dongle_public.pem`). `master.key` adalah
> kunci induk semua data terenkripsi di database. Jika hilang, data terenkripsi tidak bisa dibuka lagi.
> Kalau memindahkan database ke laptop lain, salin juga folder `config/`.

## 4. Pemetaan ketentuan proyek

| # | Ketentuan | Implementasi | Lokasi kode |
|---|---|---|---|
| 1 | Login biometrik & hanya hidup dengan dongle | **Dongle**: tanda tangan digital Ed25519 terikat nomor seri volume flashdisk, dicek setiap interaksi (flashdisk dicabut → aplikasi terkunci). **Biometrik**: deteksi wajah Haar Cascade + fitur LBPH (grid 8×8, pola uniform), login 2 langkah (password → wajah), maksimal 3 percobaan, template wajah terenkripsi AES. | `modules/auth.py`, `buat_dongle.py`, `modules/biometric.py`, `ui/login.py`, `ui/profile.py` |
| 2 | Login memakai algoritma kriptografi | Password: PBKDF2-HMAC-SHA256 100.000 iterasi + salt 16 byte, perbandingan waktu-konstan. Sesi: token bertanda tangan HMAC-SHA256. | `modules/auth.py`, `app.py` |
| 3 | Pesan teks super-enkripsi (klasik + modern) | **Extended Vigenère (mod 256) → AES-256-GCM**, dipakai untuk soal per baris, kunci jawaban, jawaban mahasiswa, token teks, kunci PDF, dan menu **💬 Pesan** (ada pratinjau tiap lapisan). | `modules/crypto_store.py`, `modules/question_bank.py`, `modules/messages.py` |
| 4 | File dienkripsi dengan algoritma berbeda | PDF memakai **ChaCha20-Poly1305** (bukan AES), dengan kunci diturunkan PBKDF2-SHA256 + salt. File `.enc` berisi header + ciphertext, dan integritas dicek dengan SHA-256. | `modules/modern_cipher.py`, `modules/exam_access.py` |
| 5 | Pesan penting terenkripsi di basis data | Soal, opsi, kunci jawaban, jawaban, token (hash PBKDF2 + salinan terenkripsi), kunci PDF, gambar token, template wajah, dan pesan semuanya terenkripsi. Setiap jenis data memakai sub-kunci HKDF tersendiri dari `master.key`. Data lama yang masih plaintext dimigrasi otomatis. | `modules/crypto_store.py`, `modules/migrations.py` |
| 6 | Pesan gambar diamankan steganografi | **Token ujian berupa gambar** (tab 🖼️ Token Steganografi): payload terenkripsi disisipkan di LSB gambar. Gambar tampak sama (PSNR > 70 dB), tetapi hanya gambar token yang membuka ujian. Juga **lampiran pesan gambar** di menu Pesan (opsional dengan sandi). | `modules/steganography.py`, `modules/stego_token.py`, `ui/kelola.py` |
| 7 | Aset penting diamankan blockchain | Rantai blok SHA-256. Setiap aset (bank soal, file PDF, gambar token, nilai, template wajah) dicatat sidik jarinya. Tab **🛡️ Integritas Aset** mendeteksi manipulasi langsung di database (mis. nilai diubah lewat phpMyAdmin). | `modules/blockchain.py`, `modules/integrity.py`, `ui/blockchain_page.py` |

Status ketujuh ketentuan juga tampil langsung di **Dashboard** dosen.

## 5. Skenario demo singkat

1. **Dongle**: cabut flashdisk → muat ulang halaman → aplikasi terkunci. Colokkan lagi → aplikasi terbuka.
2. **Biometrik**: daftarkan wajah di Profil → logout → login → password benar tetapi masih diminta verifikasi wajah.
3. **Token gambar**: Kelola Ujian → 🖼️ Token Steganografi → pilih ujian → sisipkan token → unduh PNG.
   Di tab *Uji Gambar*, unggah gambar sampul aslinya: terlihat sama, tetapi ditolak.
4. **Masa berlaku**: atur jam berakhir token beberapa menit ke depan → setelah lewat, token teks, kunci PDF,
   maupun gambar token sama-sama ditolak.
5. **Ciphertext**: di akun mahasiswa, unduh `.enc` sebelum token berlaku, lalu buka di menu
   *🔓 Buka File Ciphertext* setelah token berlaku.
6. **Blockchain**: ubah nilai di phpMyAdmin → Blockchain Log → 🛡️ Integritas Aset menampilkan ❌ DIMANIPULASI.
