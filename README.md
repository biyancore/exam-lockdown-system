# Secure Exam Dashboard

Proyek akhir Kriptografi berbasis Streamlit dan MySQL: soal pilihan ganda, lampiran PDF terenkripsi, token gambar per mahasiswa, dan log aktivitas berantai hash.

## Menjalankan di Windows

1. Aktifkan MySQL di XAMPP.
2. Buat database `secure_exam_db` di phpMyAdmin, pilih database tersebut, lalu impor dump SQL dari Biyan. Dump belum disertakan di repositori ini.
3. Buka PowerShell di folder yang berisi `app.py`, lalu jalankan:

   ```powershell
   python -m pip install -r requirements.txt
   python -m streamlit run app.py
   ```

4. Buka alamat lokal dari terminal. Login dengan akun yang tersedia di database. Password tidak dapat dibaca dari hash; jangan menimpa akun lama hanya untuk mencoba login.

Koneksi mengikuti `modules/database.py`: host `localhost`, user `root`, password kosong. Sesuaikan jika konfigurasi MySQL berbeda. Nama database dapat diatur melalui variabel lingkungan `SECURE_EXAM_DB`. File `config/dongle.key` yang valid masih diperlukan oleh mekanisme dongle simulasi yang sudah ada.

## Alur dosen dan mahasiswa

**Dosen:**

1. Buat ujian dan soal pilihan ganda pada **Kelola Ujian → Buat Ujian Baru**.
2. Buka **Daftar & Kelola Ujian**. Di bagian **PDF dan token gambar**, pilih ujian.
3. Unggah PDF dan klik **Enkripsi dan simpan PDF**. PDF dienkripsi dengan ChaCha20-Poly1305 dan disimpan sebagai BLOB di MySQL. **Unduh PDF tersimpan** menyediakan hasil dekripsinya.
4. Pilih mahasiswa, unggah PNG/JPEG sebagai sampul, tentukan masa berlaku, lalu klik **Buat token gambar**.
5. Unduh token PNG dan berikan file aslinya kepada mahasiswa tersebut. Kirim sebagai dokumen/file agar tidak dikompresi. Penerbitan ulang membatalkan token dan akses terdahulu untuk pasangan mahasiswa dan ujian itu.

**Mahasiswa:**

1. Buka **Ujian Saya**, klik **Mulai Ujian**, unggah PNG asli, lalu **Verifikasi & Mulai**.
2. Token yang sesuai akun, ujian, masa berlaku, dan catatan database membuka soal serta **Unduh soal PDF** jika PDF tersedia.
3. Setelah refresh, login dan menu dipulihkan oleh mekanisme sesi yang sudah ada. Klik **Lanjutkan ujian** tanpa mengunggah ulang token selama masih berlaku. Jawaban yang belum dikirim dan posisi soal belum disimpan saat refresh penuh.

PDF merupakan lampiran ujian pilihan ganda. Pengumpulan jawaban PDF belum dibuat. Token akun lain, token lama yang diganti, gambar biasa, dan token kedaluwarsa ditolak. Token mengikat akun, bukan membuktikan identitas fisik pemakainya; PDF yang sudah diunduh dapat disalin pengguna.

## Kriptografi dan database

- PDF: ChaCha20-Poly1305, nonce acak, ID ujian sebagai associated data.
- Token: payload ID ujian, ID mahasiswa, kedaluwarsa, dan ID acak; diproses dengan extended Vigenère pada byte lalu AES-256-GCM. Hasil berbeda pada setiap penerbitan. Payload ini bukan token teks bersama milik dosen.
- Gambar: bit LSB pada kanal RGB dengan header dan panjang payload, disimpan ulang sebagai PNG.
- Kunci PDF, Vigenère, dan AES diturunkan terpisah melalui HKDF-SHA256 dari kunci lokal 32 byte.
- Tabel `secure_exam_pdfs` dan `secure_exam_tokens` dibuat otomatis saat aplikasi dimulai, termasuk migrasi kolom `unlocked_at`. Tabel lama dipertahankan; `exams.token_hash` tidak lagi dipakai sebagai izin masuk ujian.
- PDF terenkripsi, PNG token, digest token, masa berlaku, dan waktu pembukaan akses disimpan di database. Log `UPLOAD_PDF` menyimpan hash PDF; `ISSUE_IMAGE_TOKEN` menyimpan ID ujian dan mahasiswa tanpa kunci atau token mentah.

**Cadangkan `config/exam_data.key` bersama backup database.** File dibuat saat fitur kriptografi pertama kali dipakai dan tidak masuk Git. Jika hilang, pulihkan kunci yang sama; kunci baru tidak dapat membuka data lama. `config/session.key` juga tidak masuk Git. Untuk pengujian terpisah, lokasi kunci data dapat diatur melalui `SECURE_EXAM_KEY_PATH`.

PDF dibatasi 10 MB dan diperiksa melalui header `%PDF-`; ini bukan parser lengkap atau pemeriksaan isi dokumen. Gambar dibatasi 8 juta piksel dan harus cukup besar untuk token. Penyimpanan juga mengikuti `max_allowed_packet` MySQL dengan ruang tambahan untuk encoding query. Pada XAMPP dengan batas paket 1 MB, gunakan file di bawah sekitar 500 KB. Untuk berkas lebih besar, atur `max_allowed_packet=64M` di bagian `[mysqld]` konfigurasi MySQL melalui XAMPP, lalu restart MySQL.

Biometrik dan dongle mengikuti implementasi awal: dongle berupa file simulasi dan webcam mendeteksi keberadaan wajah. Penyempurnaan verifikasi identitas, keamanan sesi, dan modul kriptografi lama berada di luar perubahan PDF/token ini.

## Pengujian

**Cara termudah.** Skrip ini menyiapkan database uji, menjalankan semua uji otomatis, membuka aplikasi di http://127.0.0.1:8511, lalu menghapus database uji saat kamu menekan Ctrl+C:

```powershell
powershell -ExecutionPolicy Bypass -File tests/uji_lokal.ps1
```

Tambahkan `-HanyaUji` bila hanya ingin menjalankan tes tanpa membuka aplikasi. Database asli `secure_exam_db` tidak disentuh.

Berkas contoh siap pakai ada di `data/contoh_soal`:

- `soal_ujian_kriptografi.pdf` untuk diunggah pada bagian PDF dan token gambar.
- `sampul_token.png` untuk membuat token gambar mahasiswa.
- `soal_untuk_formulir.txt` berisi lima soal beserta pilihan dan kunci untuk disalin ke bank soal.

PDF dan PNG tersebut sudah diuji: PDF dapat diunggah, token dari PNG membuka lima soal, dan PDF yang diunduh mahasiswa identik byte-per-byte dengan aslinya (SHA-256 `6e5b8451...dbc9cb`, 3.846 byte).

Buat ulang berkas contoh dengan `python buat_contoh.py`. Untuk melihat tampilan PDF tanpa membuka aplikasi, gunakan `python -m pip install pypdfium2` lalu render halaman PDF menjadi gambar.

Perintah manualnya:

Uji kriptografi tanpa MySQL:

```powershell
python -m unittest discover -s tests -p "test_*.py" -v
```

Uji integrasi memakai database lokal terpisah `secure_exam_e2e_codex`. Fixture menyalin struktur tabel, bukan data pengguna, dari `secure_exam_db` dan membuat akun sintetis:

```powershell
python tests/browser_fixture.py setup
$env:SECURE_EXAM_DB="secure_exam_e2e_codex"
$env:SECURE_EXAM_KEY_PATH="data/browser_test/exam_data.key"
python test_pdf_token_integration.py
python test_exam_ui.py
# Opsional: uji browser pada port terpisah, hentikan dengan Ctrl+C.
python -m streamlit run app.py --server.port 8511
```

Akun sintetis: `uji_dosen`, `uji_mahasiswa`, `uji_lain`; password semuanya `UjiLokal2026!`. Akun hanya dibuat dalam database uji. Setelah selesai dan server uji dihentikan:

```powershell
python tests/browser_fixture.py cleanup
Remove-Item Env:SECURE_EXAM_DB
Remove-Item Env:SECURE_EXAM_KEY_PATH
```
