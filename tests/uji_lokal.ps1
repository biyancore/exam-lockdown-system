param(
    [switch]$HanyaUji
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent
Set-Location $repo

$env:SECURE_EXAM_DB = 'secure_exam_e2e_codex'
$env:SECURE_EXAM_KEY_PATH = 'data/browser_test/exam_data.key'

try {
    Write-Host ''
    Write-Host '[1/4] Menyiapkan database uji terpisah...' -ForegroundColor Cyan
    python tests/browser_fixture.py setup

    Write-Host ''
    Write-Host '[2/4] Uji kriptografi (tanpa MySQL)...' -ForegroundColor Cyan
    python -m unittest discover -s tests -p 'test_*.py'
    if ($LASTEXITCODE -ne 0) { throw 'Uji kriptografi gagal.' }

    Write-Host ''
    Write-Host '[3/4] Uji integrasi PDF, token, dan database...' -ForegroundColor Cyan
    python test_pdf_token_integration.py
    if ($LASTEXITCODE -ne 0) { throw 'Uji integrasi gagal.' }
    python test_exam_ui.py
    if ($LASTEXITCODE -ne 0) { throw 'Uji tampilan gagal.' }

    Write-Host ''
    Write-Host 'Semua uji otomatis lulus.' -ForegroundColor Green

    if (-not $HanyaUji) {
        Write-Host ''
        Write-Host '[4/4] Membuka aplikasi UJI di http://127.0.0.1:8511' -ForegroundColor Cyan
        Write-Host 'Akun uji (database terpisah, bukan akun asli):'
        Write-Host '  Dosen      : uji_dosen'
        Write-Host '  Mahasiswa  : uji_mahasiswa'
        Write-Host '  Mahasiswa 2: uji_lain'
        Write-Host '  Password   : UjiLokal2026!'
        Write-Host ''
        Write-Host 'Skenario manual:'
        Write-Host '  1. Login uji_dosen, buat ujian (Kelola Ujian -> Buat Ujian Baru).'
        Write-Host '     Salin isi data/contoh_soal/soal_untuk_formulir.txt (5 soal).'
        Write-Host '  2. Buka tab Daftar & Kelola Ujian, unggah data/contoh_soal/soal_ujian_kriptografi.pdf,'
        Write-Host '     klik Enkripsi dan simpan PDF.'
        Write-Host '  3. Pilih uji_mahasiswa, unggah data/contoh_soal/sampul_token.png,'
        Write-Host '     klik Buat token gambar lalu Unduh token PNG.'
        Write-Host '  4. Coba dulu login uji_lain dan pakai PNG itu: harus DITOLAK.'
        Write-Host '  5. Login uji_mahasiswa, unggah PNG yang sama: soal dan PDF terbuka.'
        Write-Host '  6. Refresh browser: tetap di Ujian Saya, muncul Lanjutkan ujian.'
        Write-Host ''
        Write-Host 'Hentikan server dengan Ctrl+C untuk membersihkan database uji.' -ForegroundColor Yellow
        python -m streamlit run app.py --server.port 8511 --server.address 127.0.0.1 --browser.gatherUsageStats false
    }
}
finally {
    Write-Host ''
    Write-Host 'Membersihkan database uji...' -ForegroundColor Cyan
    python tests/browser_fixture.py cleanup
    Remove-Item Env:SECURE_EXAM_DB -ErrorAction SilentlyContinue
    Remove-Item Env:SECURE_EXAM_KEY_PATH -ErrorAction SilentlyContinue
}
