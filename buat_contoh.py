"""Membuat contoh soal PDF dan gambar sampul PNG untuk uji coba."""
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont

OUT = Path('data/contoh_soal')
W, H = 1240, 1754
FONT_DIR = Path('C:/Windows/Fonts')
PDF_WIDTH = 480


def font(name, size):
    try:
        return ImageFont.truetype(str(FONT_DIR / name), size)
    except OSError:
        return ImageFont.load_default()


def text_width(text, size, bold=False):
    f = font('arialbd.ttf' if bold else 'arial.ttf', int(size * 1.35))
    return f.getlength(text) / 1.35


def wrap(text, size, bold=False, width=PDF_WIDTH):
    words, lines, current = text.split(), [], ''
    for word in words:
        trial = f'{current} {word}'.strip()
        if current and text_width(trial, size, bold) > width:
            lines.append(current)
            current = word
        else:
            current = trial
    if current:
        lines.append(current)
    return lines or ['']


def esc(text):
    return text.replace('\\', r'\\').replace('(', r'\(').replace(')', r'\)')


def build_pdf(blocks):
    pages, page, y = [], [], 792
    for bold, size, text, gap in blocks:
        for line in wrap(text, size, bold):
            if y < 70:
                pages.append(page)
                page, y = [], 792
            page.append((bold, size, line, y))
            y -= size + 5
        y -= gap
    if page:
        pages.append(page)

    objects, page_ids = [], []
    next_id = 3
    for _ in pages:
        page_ids.append(next_id)
        next_id += 2
    regular, bold_font = next_id, next_id + 1

    objects.append(b'<< /Type /Catalog /Pages 2 0 R >>')
    kids = ' '.join(f'{i} 0 R' for i in page_ids)
    objects.append(f'<< /Type /Pages /Kids [{kids}] /Count {len(pages)} >>'.encode())
    for index, (page_id, lines) in enumerate(zip(page_ids, pages), 1):
        ops = []
        for bold, size, line, y in lines:
            ops.append(f'BT /{"F2" if bold else "F1"} {size} Tf 50 {y} Td ({esc(line)}) Tj ET')
        ops.append(f'BT /F1 8 Tf 280 40 Td (Halaman {index} dari {len(pages)}) Tj ET')
        stream = '\n'.join(ops).encode('latin-1')
        objects.append(
            f'<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] '
            f'/Resources << /Font << /F1 {regular} 0 R /F2 {bold_font} 0 R >> >> '
            f'/Contents {page_id + 1} 0 R >>'.encode())
        objects.append(f'<< /Length {len(stream)} >>\nstream\n'.encode() + stream + b'\nendstream')
    objects.append(b'<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>')
    objects.append(b'<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>')

    out = bytearray(b'%PDF-1.4\n%\xe2\xe3\xcf\xd3\n')
    offsets = []
    for number, body in enumerate(objects, 1):
        offsets.append(len(out))
        out += f'{number} 0 obj\n'.encode() + body + b'\nendobj\n'
    xref = len(out)
    out += f'xref\n0 {len(objects) + 1}\n0000000000 65535 f \n'.encode()
    for offset in offsets:
        out += f'{offset:010} 00000 n \n'.encode()
    out += (f'trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\n'
            f'startxref\n{xref}\n%%EOF\n').encode()
    return bytes(out)


SOAL = [
    ('Algoritma kriptografi modern yang dipakai untuk mengenkripsi file PDF pada aplikasi ini adalah...',
     ['ChaCha20-Poly1305', 'Caesar Cipher', 'Vigenere Cipher', 'Least Significant Bit']),
    ('Teknik yang dipakai untuk menyembunyikan token ujian di dalam gambar PNG adalah...',
     ['Steganografi LSB', 'Base64 encoding', 'Hashing SHA-256', 'Kompresi ZIP']),
    ('Sebelum dienkripsi dengan AES-256-GCM, payload token ujian diacak lebih dulu memakai cipher klasik...',
     ['Vigenere', 'Rail Fence', 'Playfair', 'Enigma']),
    ('Fungsi yang dipakai untuk menyimpan password pengguna dalam bentuk hash adalah...',
     ['PBKDF2-SHA256', 'MD5 tanpa salt', 'Base64', 'ROT13']),
    ('Teknologi yang menjaga integritas riwayat nilai dan aktivitas ujian adalah...',
     ['Blockchain dengan hash SHA-256', 'Cookie browser', 'Session Storage', 'Cache server']),
]

def soal_blocks():
    blocks = [
        (True, 15, 'UJIAN AKHIR SEMESTER - KRIPTOGRAFI', 4),
        (False, 11, 'Universitas Pembangunan Nasional "Veteran" Yogyakarta', 6),
        (False, 10, 'Mata Kuliah: Kriptografi   |   Sifat: Tutup buku   |   Waktu: 90 menit', 2),
        (False, 10, 'Kode Ujian: KRIPTO-2026-A', 12),
        (True, 11, 'PETUNJUK PENGERJAAN', 4),
        (False, 10, '1. Soal ini hanya dapat dibuka setelah token gambar diverifikasi oleh sistem.', 0),
        (False, 10, '2. Pilih satu jawaban yang paling tepat pada setiap nomor.', 0),
        (False, 10, '3. Jawaban dikumpulkan melalui menu Ujian Saya di aplikasi.', 12),
        (True, 12, 'A. PILIHAN GANDA', 6),
    ]
    for number, (question, options) in enumerate(SOAL, 1):
        blocks.append((True, 10, f'{number}. {question}', 2))
        for letter, option in zip('ABCD', options):
            blocks.append((False, 10, f'    {letter}. {option}', 0))
        blocks.append((False, 10, '', 6))
    blocks.append((True, 12, 'B. KETENTUAN PENILAIAN', 6))
    blocks.append((False, 10, 'Setiap jawaban benar bernilai 20 poin. Total nilai maksimal 100.', 2))
    blocks.append((False, 10, 'Nilai dihitung otomatis saat jawaban dikumpulkan melalui aplikasi.', 10))
    blocks.append((False, 9, '-- Akhir berkas soal. Dokumen ini dienkripsi saat diunggah ke sistem. --', 0))
    return blocks


def buat_pdf():
    data = build_pdf(soal_blocks())
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / 'soal_ujian_kriptografi.pdf').write_bytes(data)
    return len(data)


def centered(draw, y, text, fnt, fill):
    draw.text(((W - draw.textlength(text, font=fnt)) / 2, y), text, font=fnt, fill=fill)


def buat_sampul():
    img = Image.new('RGB', (W, H), '#0b2545')
    draw = ImageDraw.Draw(img)
    for y in range(H):
        t = y / H
        draw.line([(0, y), (W, y)], fill=(
            int(11 + 15 * t), int(37 + 45 * t), int(69 + 55 * t)))
    for i in range(28):
        draw.ellipse([W - 380 + i * 9, -180 + i * 9, W + 200 - i * 4, 420 - i * 4],
                     outline=(30 + i * 3, 90 + i * 4, 120 + i * 3), width=2)

    draw.rounded_rectangle([90, 150, W - 90, H - 150], radius=36, fill='#ffffff')
    draw.rounded_rectangle([90, 150, W - 90, 300], radius=36, fill='#0f766e')
    draw.rectangle([90, 260, W - 90, 300], fill='#0f766e')

    centered(draw, 190, 'KARTU TOKEN UJIAN', font('arialbd.ttf', 54), 'white')
    draw.text((150, 350), 'SPADA UPN', font=font('arialbd.ttf', 76), fill='#0b2545')
    draw.text((152, 450), 'Secure Exam System', font=font('arial.ttf', 34), fill='#475569')

    draw.line([(150, 520), (W - 150, 520)], fill='#cbd5e1', width=3)

    draw.text((150, 570), 'MATA KULIAH', font=font('arialbd.ttf', 24), fill='#0f766e')
    draw.text((150, 605), 'Kriptografi', font=font('arialbd.ttf', 46), fill='#0b2545')
    draw.text((150, 690), 'KODE UJIAN', font=font('arialbd.ttf', 24), fill='#0f766e')
    draw.text((150, 725), 'KRIPTO-2026-A', font=font('arial.ttf', 38), fill='#0b2545')

    draw.rounded_rectangle([150, 830, W - 150, 1010], radius=20, fill='#f1f5f9')
    draw.text((180, 860), 'PETUNJUK', font=font('arialbd.ttf', 26), fill='#0f766e')
    draw.text((180, 905), '1. Unggah file PNG ini pada menu Ujian Saya.', font=font('arial.ttf', 26), fill='#334155')
    draw.text((180, 950), '2. Jangan ubah ukuran atau mengompres gambar.', font=font('arial.ttf', 26), fill='#334155')

    draw.text((150, 1085), 'Token ujian tersembunyi di dalam piksel gambar ini', font=font('arial.ttf', 26), fill='#475569')
    draw.text((150, 1125), 'menggunakan steganografi LSB. Token hanya berlaku', font=font('arial.ttf', 26), fill='#475569')
    draw.text((150, 1165), 'untuk satu mahasiswa dan satu ujian tertentu.', font=font('arial.ttf', 26), fill='#475569')

    draw.line([(150, 1250), (W - 150, 1250)], fill='#cbd5e1', width=3)
    draw.text((150, 1285), 'Diterbitkan oleh:', font=font('arial.ttf', 24), fill='#64748b')
    draw.text((150, 1320), 'Dosen Pengampu Kriptografi', font=font('arialbd.ttf', 30), fill='#0b2545')
    draw.text((150, 1400), 'Simpan berkas ini. Token tidak dapat dipakai oleh akun lain.',
              font=font('arial.ttf', 23), fill='#94a3b8')

    OUT.mkdir(parents=True, exist_ok=True)
    img.save(OUT / 'sampul_token.png', format='PNG')
    return img.size


if __name__ == '__main__':
    print('PDF:', buat_pdf(), 'byte')
    print('PNG:', buat_sampul())

