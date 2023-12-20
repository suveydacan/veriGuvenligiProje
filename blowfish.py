from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from os import urandom

def encrypt_file(input_file_path, key):
    with open(input_file_path, 'rb') as file:
        plaintext = file.read()

    # Blowfish'in blok boyutu 8 bayttır (64 bit)
    block_size = 8

    # Veriyi blok boyutuna uygun şekilde doldurun
    padder = padding.PKCS7(block_size * 8).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()

    cipher = Cipher(algorithms.Blowfish(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

    output_file_path = "encrypted_" + input_file_path

    with open(output_file_path, 'wb') as file:
        file.write(ciphertext)

    return output_file_path

def decrypt_file(input_file_path, key):
    with open(input_file_path, 'rb') as file:
        ciphertext = file.read()

    cipher = Cipher(algorithms.Blowfish(key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # Blok boyutuna uygun şekilde doldurulan veriyi geri çıkarın
    unpadder = padding.PKCS7(8 * 8).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    output_file_path = "decrypted_" + input_file_path

    with open(output_file_path, 'wb') as file:
        file.write(plaintext)

# Anahtarınızı (32-448 bit arasında) oluşturun (örneğin, 256 bit için):
key = b'my_secret_key_for_blowfish256'

# Örnek kullanım
input_file_path = 'sample.pdf'

# Dosyayı şifrele
encrypted_file_path = encrypt_file(input_file_path, key)
print(f"Şifrelenmiş dosya: {encrypted_file_path}")

# Şifreli dosyayı çöz
decrypted_file_path = decrypt_file(encrypted_file_path, key)
print(f"Çözülmüş dosya: {decrypted_file_path}") #çıktı da none gözüküyor.
