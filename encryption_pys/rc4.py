from Crypto.Cipher import ARC4
from Crypto.Random import get_random_bytes
import csv

def rc4_encrypt(key, plaintext):
    cipher = ARC4.new(key)
    ciphertext = cipher.encrypt(plaintext)
    return ciphertext

def rc4_decrypt(key, ciphertext):
    cipher = ARC4.new(key)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext

def encrypt_csv_with_rc4(key, csv_data):
    encrypted_data_csv=[]
     # CSV verisini RC4 kullanarak şifrele
    for row in csv_data:
        encrypted_row = [rc4_encrypt(key, data.encode()) for data in row]
        encrypted_data_csv.append(encrypted_row)
    
    return encrypted_data_csv

def decrypt_csv_with_rc4(key, encrypted_data):
    plaintext_data_csv=[]
   
    for row in encrypted_data:
            # RC4 kullanarak veriyi çöz
            decrypted_data_row = [rc4_decrypt(key,data) for data in row]
            decrypted_row = [data.decode('utf-8') for data in decrypted_data_row]
            plaintext_data_csv.append(decrypted_row)

    return plaintext_data_csv

# Kullanım örneği
encryption_key = b'SecretKey123'  # Anahtarınızı güvenli bir şekilde saklayın

# CSV verilerini dosyadan oku
data_list = []

with open("sifresizVeri.csv", 'r') as csvfile:
    csv_reader = csv.reader(csvfile)
        
    for row in csv_reader:
        data_list.append(row)

print("orijinal veri", data_list)

# CSV verisini şifrele
encrypted_result = encrypt_csv_with_rc4(encryption_key, data_list)
print("Şifrelenmiş Veri:", encrypted_result)


 # Şifrelenmiş CSV dosyasına bilgileri yazma
with open("sifreliVeri.csv", "a", newline='') as dosya:
    # CSV dosyasına yazmak için bir yazıcı oluştur
    csv_writer = csv.writer(dosya)
    # Veriyi CSV dosyasına yaz
    csv_writer.writerows(encrypted_result)

# Şifrelenmiş JSON verisini çöz
decrypted_result = decrypt_csv_with_rc4(encryption_key, encrypted_result)
print("Çözülen Veri:", decrypted_result)
