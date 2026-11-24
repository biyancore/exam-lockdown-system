# SRIKANDI — Secure Exam System

Aplikasi ujian daring (Streamlit + MySQL/MariaDB XAMPP) yang menerapkan kriptografi klasik, modern,
steganografi, biometrik, dongle, dan blockchain sederhana.

## 1. Instalasi

```bash
python -m pip install -r requirements.txt
```

> Butuh **Streamlit 1.50 atau lebih baru**. Jika versi lama sudah terpasang: `python -m pip install -U streamlit`.

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

> 📷 Kamera browser hanya aktif jika aplikasi dibuka lewat `http://localhost:8501` (atau HTTPS). Membuka lewat
> *Network URL* (`http://192.168.x.x:8501`) dari perangkat lain membuat kamera diblokir browser, sehingga
> verifikasi wajah tidak bisa dilakukan.

> ⚠️ **Simpan folder `config/`** (`master.key`, `session.key`, `dongle_public.pem`). `master.key` adalah
> kunci induk semua data terenkripsi di database. Jika hilang, data terenkripsi tidak bisa dibuka lagi.
> Kalau memindahkan database ke laptop lain, salin juga folder `config/`.

## 4. Pemetaan ketentuan proyek

| # | Ketentuan | Implementasi | Lokasi kode |
|---|---|---|---|
| 1 | Login biometrik & hanya hidup dengan dongle | **Dongle**: tanda tangan digital Ed25519 terikat nomor seri volume flashdisk, dicek setiap interaksi (flashdisk dicabut → aplikasi terkunci). **Biometrik**: deteksi wajah Haar Cascade + fitur LBPH (grid 8×8, pola uniform), login 2 langkah (password → wajah), gagal 3 kali → verifikasi wajah dikunci 5 menit, template wajah terenkripsi AES. Logout membatalkan semua link sesi lama. | `modules/auth.py`, `buat_dongle.py`, `modules/biometric.py`, `modules/session.py`, `ui/login.py`, `ui/profile.py` |
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

## 6. Catatan perbaikan (12 Nov 2026)

**Biometrik / login**
- Link sesi lama (dibuat saat login password saja, sebelum Face ID didaftarkan) dulu tetap bisa masuk **tanpa
  verifikasi wajah**. Sekarang token sesi mencatat cara login (`pwd`/`face`); token `pwd` milik akun ber-Face ID
  diarahkan ke langkah verifikasi wajah.
- Logout kini membatalkan semua link sesi lama milik akun itu (dulu link di riwayat browser masih berlaku 7 hari).
- Batas 3 percobaan wajah dulu bisa diulang tanpa batas dengan login ulang. Sekarang gagal 3 kali → dikunci
  5 menit (tersimpan di database). Foto tanpa wajah tidak lagi menghabiskan jatah percobaan.
- Template wajah yang rusak / tidak bisa didekripsi (mis. `master.key` berbeda) dulu membuat halaman Profil
  error dan pengguna tidak bisa mendaftar ulang. Sekarang muncul pesan + tombol hapus untuk daftar ulang.
- Foto rusak/kosong tidak lagi membuat aplikasi crash.
- Template disimpan dalam format ringkas (±70x lebih kecil, aman untuk `max_allowed_packet` XAMPP). Template
  lama tetap terbaca.
- Template wajah yang dihapus langsung di database (mematikan Face ID diam-diam) kini terdeteksi di
  **🛡️ Integritas Aset** sebagai ❌ DIMANIPULASI.
- Pilihan "Uji verifikasi wajah" hanya muncul jika biometrik sudah aktif. Setelah pendaftaran selesai,
  refresh halaman tidak lagi meminta verifikasi wajah.

**Umum**
- Menjalankan `streamlit run` dari folder lain dulu membuat `config/*.key` baru di folder yang salah
  (aplikasi terkunci / data gagal didekripsi). Sekarang aplikasi selalu memakai folder proyeknya sendiri.
- Ujian PG: soal yang hanya dilihat dulu otomatis terjawab **A** (nilai bisa salah). Sekarang soal yang belum
  dipilih tetap kosong, dan ada penghitung "Terjawab x dari n".
- Struktur database kompatibel dengan MySQL 8 (dulu `ADD COLUMN IF NOT EXISTS` hanya jalan di MariaDB),
  dan pengecekan struktur cukup sekali per sesi (aplikasi lebih cepat).
- Pesan jelas jika MySQL belum berjalan. API Streamlit yang deprecated (`components.html`,
  `use_container_width`) diganti.
