def extended_vigenere_encrypt(plain_text, key):
    """
    Enkripsi Extended Vigenère Cipher (mendukung seluruh karakter ASCII 0-255).
    
    Parameter:
    - plain_text: Teks asli (string)
    - key: Kunci rahasia (string)
    
    Output:
    - string terenkripsi (dalam bentuk bytes yang di-encode ke latin1 agar aman disimpan)
    """
    if not key:
        key = "DEFAULTKEY"
        
    encrypted_chars = []
    key_length = len(key)
    
    for i, char in enumerate(plain_text):
        p = ord(char)
        k = ord(key[i % key_length])
        # Rumus Extended Vigenère: C = (P + K) mod 256
        c = (p + k) % 256
        encrypted_chars.append(chr(c))
        
    return "".join(encrypted_chars)

def extended_vigenere_decrypt(cipher_text, key):
    """
    Dekripsi Extended Vigenère Cipher.
    
    Parameter:
    - cipher_text: Teks terenkripsi (string)
    - key: Kunci rahasia (string)
    
    Output:
    - string asli (plain text)
    """
    if not key:
        key = "DEFAULTKEY"
        
    decrypted_chars = []
    key_length = len(key)
    
    for i, char in enumerate(cipher_text):
        c = ord(char)
        k = ord(key[i % key_length])
        # Rumus Dekripsi Extended Vigenère: P = (C - K + 256) mod 256
        p = (c - k + 256) % 256
        decrypted_chars.append(chr(p))
        
    return "".join(decrypted_chars)