file_path = 'C:/Users/Pc/Desktop/veriGuvenligiProje/project/website_app/media/encrypted_files/2_plan.png'
file_path2 = 'C:/Users/Pc/Desktop/veriGuvenligiProje/project/website_app/media/encrypted_files/plan.png'
plaintext = None
with open(file_path, 'rb+') as file:
        plaintext = file.read()
with open(file_path2, 'wb+') as file:
       file.write(plaintext)