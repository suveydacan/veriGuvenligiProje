from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes
import os

def pad(data):
    # Veriyi 8 byte'lık bloklara uygun hale getir
    length = 8 - (len(data) % 8)
    return data + bytes([length] * length)

def unpad(data):
    # Veriden çıkartılan dolguyu kaldır
    return data[:-data[-1]]

def encrypt_file(input_file_path, key):
    cipher = DES.new(key, DES.MODE_ECB)

    with open(input_file_path, 'rb') as file:
        plaintext = file.read()

    plaintext = pad(plaintext)
    ciphertext = cipher.encrypt(plaintext)

    output_file_path ="encrypted_" +  input_file_path
    with open(output_file_path, 'wb') as file:
        file.write(ciphertext)

    return output_file_path

def decrypt_file(input_file_path, key):
    cipher = DES.new(key, DES.MODE_ECB)

    with open(input_file_path, 'rb') as file:
        ciphertext = file.read()

    plaintext = cipher.decrypt(ciphertext)
    plaintext = unpad(plaintext)

    output_file_path = "decrypted_" + input_file_path

    with open(output_file_path, 'wb') as file:
        file.write(plaintext)

    return output_file_path

# Örnek kullanım
input_file_path = 'sample.pdf'

# 8 byte'lık bir anahtar kullanılıyor
key = b'suveyda6'

# Dosyayı şifrele
encrypted_file_path = encrypt_file(input_file_path, key)
print(f"Şifrelenmiş dosya: {encrypted_file_path}")

# Şifreli dosyayı çöz
decrypted_file_path = decrypt_file(encrypted_file_path, key)
print(f"Çözülmüş dosya: {decrypted_file_path}")

