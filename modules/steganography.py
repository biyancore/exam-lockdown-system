from PIL import Image

def encode_image(image_path, secret_message, output_path):
    """
    Menyembunyikan pesan rahasia (misal: token ujian) ke dalam gambar 
    menggunakan teknik LSB (Least Significant Bit).
    
    Parameter:
    - image_path: Path gambar asli (misal: 'assets/default_exam_bg.jpg')
    - secret_message: Teks token/pesan yang ingin disembunyikan
    - output_path: Path penyimpanan gambar hasil steganografi (stego_image)
    """
    try:
        image = Image.open(image_path)
        if image.mode != 'RGB':
            image = image.convert('RGB')
        
        encoded_image = image.copy()
        width, height = encoded_image.size
        
        # Tambahkan delimiter penanda akhir pesan
        secret_message += "###EXAM_TOKEN_END###"
        binary_message = ''.join(format(ord(char), '08b') for char in secret_message)
        
        data_index = 0
        message_length = len(binary_message)
        
        # Cek kapasitas gambar
        max_capacity = width * height * 3
        if message_length > max_capacity:
            return False, "Pesan terlalu besar untuk disembunyikan dalam gambar ini!"
        
        pixels = encoded_image.load()
        for y in range(height):
            for x in range(width):
                if data_index < message_length:
                    r, g, b = pixels[x, y]
                    
                    # Ubah bit terakhir (LSB) dari channel R, G, dan B
                    if data_index < message_length:
                        r = (r & ~1) | int(binary_message[data_index])
                        data_index += 1
                    if data_index < message_length:
                        g = (g & ~1) | int(binary_message[data_index])
                        data_index += 1
                    if data_index < message_length:
                        b = (b & ~1) | int(binary_message[data_index])
                        data_index += 1
                        
                    pixels[x, y] = (r, g, b)
                else:
                    break
            if data_index >= message_length:
                break
                
        encoded_image.save(output_path)
        return True, f"Berhasil menyembunyikan token ke {output_path}"
    except Exception as e:
        return False, f"Error steganografi encode: {str(e)}"

def decode_image(image_path):
    """
    Mengekstrak pesan rahasia (token ujian) dari gambar steganografi LSB.
    
    Parameter:
    - image_path: Path gambar stego yang diunggah mahasiswa.
    """
    try:
        image = Image.open(image_path)
        if image.mode != 'RGB':
            image = image.convert('RGB')
            
        pixels = image.load()
        width, height = image.size
        
        binary_message = ""
        for y in range(height):
            for x in range(width):
                r, g, b = pixels[x, y]
                binary_message += str(r & 1)
                binary_message += str(g & 1)
                binary_message += str(b & 1)
                
        # Konversi biner ke string karakter
        chars = []
        for i in range(0, len(binary_message), 8):
            byte = binary_message[i:i+8]
            if len(byte) < 8:
                break
            char = chr(int(byte, 2))
            chars.append(char)
            
            # Cek apakah sudah mencapai delimiter penanda akhir
            current_text = "".join(chars)
            if current_text.endswith("###EXAM_TOKEN_END###"):
                return True, current_text.replace("###EXAM_TOKEN_END###", "")
                
        return False, "Token ujian tidak ditemukan di dalam gambar ini."
    except Exception as e:
        return False, f"Error steganografi decode: {str(e)}"