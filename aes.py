from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os

def encrypt_file(input_file_path, key):
    with open(input_file_path, 'rb') as file:
        plaintext = file.read()

    # Rastgele IV oluştur
    iv = os.urandom(16)

    # Cipher ve encryptor oluştur
    cipher = Cipher(algorithms.AES(key), modes.CFB8(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Padding uygula
    padder = padding.PKCS7(algorithms.AES.block_size * 8).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()

    # Şifrele
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

    output_file_path = "encrypted_" + input_file_path

    with open(output_file_path, 'wb') as file:
        file.write(iv + ciphertext)

    return output_file_path

def decrypt_file(input_file_path, key):
    with open(input_file_path, 'rb') as file:
        data = file.read()

    # IV ve ciphertext'ı ayır
    iv = data[:16]
    ciphertext = data[16:]

    # Cipher ve decryptor oluştur
    cipher = Cipher(algorithms.AES(key), modes.CFB8(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    # Şifreyi çöz ve paddingi kaldır
    decrypted_text = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size * 8).unpadder()
    unpadded_plaintext = unpadder.update(decrypted_text) + unpadder.finalize()

    output_file_path = "decrypted_" + input_file_path

    with open(output_file_path, 'wb') as file:
        file.write(unpadded_plaintext)

    return output_file_path

# Anahtarınızı (128, 192 veya 256 bit) oluşturun (örneğin, 256 bit için):
key = b'my_secret_key_for_aes256'

# Örnek kullanım
input_file_path = 'sample.png'

# Dosyayı şifrele
encrypted_file_path = encrypt_file(input_file_path, key)
print(f"Şifrelenmiş dosya: {encrypted_file_path}")

# Şifreli dosyayı çöz
decrypted_file_path = decrypt_file(encrypted_file_path, key)
print(f"Çözülmüş dosya: {decrypted_file_path}")
