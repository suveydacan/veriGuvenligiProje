from django.conf import settings
from django.template import loader
from django.http import HttpResponse, HttpResponseRedirect, QueryDict, JsonResponse
from django.shortcuts import redirect, render
from django.urls import reverse
from django.contrib.auth.models import User, Group
from django.views.generic import TemplateView, RedirectView 
from django.core.paginator import Paginator ,EmptyPage
from django.contrib import messages
from django.utils.datastructures import MultiValueDictKeyError

from django.contrib.auth import authenticate, login, logout
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt

from django.db.models.signals import post_save
from django.dispatch import receiver
from django.contrib.auth.models import User, Group

from .forms import SignUpForm, FileUploadForm

import os
from django.http import FileResponse
from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from Crypto.Cipher import ARC4
import base64
import json

from pymongo import MongoClient
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .models import *
from .serializers import FolderSerializer, FileSerializer


import os
import csv
from datetime import datetime, timedelta
from django.utils import timezone
import re
import random
from collections import defaultdict
import logging
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent



# Create your views here.


client = MongoClient()



def index(request):
    content= {}
    return render(request, 'login.html',content )
    # if request.user.is_authenticated and request.user.groups.filter(name="ClientUserGroup").exists():
    #     template = loader.get_template('analytic.html')
    #     current_user = request.user 
    #     content= {}

    #     return render(request, 'analytic.html',content )
                
    # else:
    #     return redirect("/user/login")

# Yeni bir kullanıcı kaydı oluşturulduğunda çağrılan sinyal işlevi
@receiver(post_save, sender=User)
def create_user_base_folder(sender, instance, created, **kwargs):
    if created:
        # Kullanıcı oluşturulduysa, base folder'ı oluştur
        Folder.objects.create(name='Home', type='folder', user_id=instance.id, parent_folder=None)

def signUp(request):
    if request.method == 'POST':
        form = SignUpForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            user.save()

            return redirect('login') 
    else:
        form = SignUpForm()

    context = {"error": form.errors}
    
    return render(request, 'signUp.html', {'form': form})

def logIn(request):
    context = {}
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')
        username = User.objects.get(email=email).username
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            user_id = request.user.id
            home_folder_id = Folder.objects.get(user_id=user_id, parent_folder=None).id

            return redirect('home', path=home_folder_id) 
        else:
            context.update({"error":"user none"})

    return render(request, 'login.html', context)

def log_out(request):
    context = {}
    if request.user.is_authenticated:
         logout(request)
         return render(request, 'login.html')
    else:
        context["error"] = "oturum açık değil!"
        return render(request, 'login.html',context )

def getFolders(user_id, parent_folder_id):
    # folders= Folder.objects.get(user_id=user_id, parent_folder_id=parent_folder_id) # filtreye uyan tek bir obje geri döndürmeye çalışırmış
    folders_object= Folder.objects.filter(user_id=user_id, parent_folder=parent_folder_id)
    folders = []
    for folder in folders_object:
        folder_dict = {"name":folder.name, "id":folder.id}
        folders.append(folder_dict)
    return folders

def deleteFolder(request, path, id):
    if request.user.is_authenticated and request.method == 'POST':
        user_id = request.user.id

        objects = Folder.objects.filter(user_id=user_id, id=id)
        objects.delete()

        return redirect('home', path=path)
    else:   
        return redirect('logIn')

def getFiles(user_id, parent_folder_id):
    files_object = File.objects.filter(user_id=user_id, parent_folder_id=parent_folder_id)
    files = []
    for file in files_object:
        file_dict = {"name": file.name,
                     'id': file.id,
                     'file_type': file.file_type,
                     'parent_folder': file.parent_folder_id,
                     'user_id': file.user_id,
                     "encrypt_type": file.encrypt_type,
                     "size": file.size,
                     "last_modified": file.last_modified,
                     "created": file.created,
                     "file_url": file.file_url}
        files.append(file_dict)
    return files

def deleteFile(request, path, id):
    if request.user.is_authenticated and request.method == 'POST':
        user_id = request.user.id
        path_parts = request.path.split('/')
        parent_folder_id = path_parts[-3]

        objects = File.objects.filter(user_id=user_id, parent_folder_id=parent_folder_id, id=id).first()
        if objects:   
            file_url = objects.file_url
            objects.delete()
            os.remove(os.path.join(settings.MEDIA_ROOT,'encrypted_files', file_url ))

        return redirect('home', path=path)
    else:   
        return redirect('logIn')
 
def home(request, path):
    if request.user.is_authenticated:
        content= {"path": path}

        path_parts = request.path.split('/')
        parent_folder_id = path_parts[-2]
        is_home = path_parts[-3]
        folders = getFolders(request.user.id, parent_folder_id)
        content.update({"folders":folders})

        files = getFiles(request.user.id, parent_folder_id)
        content.update({"files":files})

        form = FileUploadForm()
        content.update({"uploadForm":form})

        folder_name = ""
        if is_home == "home":
            objects = Folder.objects.filter(user_id=request.user.id, parent_folder_id=None).first()
            folder_name = objects.name
        else:
            objects = Folder.objects.filter(user_id=request.user.id, id=parent_folder_id).first()
            folder_name = objects.name
        content.update({'folder_name':folder_name})

        return render(request, 'home.html',content )
    else:   
        return redirect('logIn')

def openSubFolder(request, path, id):
    if request.user.is_authenticated:
        new_path = str(path)+"/"+str(id)

        return redirect('home', path=new_path)
    else:   
        return redirect('logIn')


def profile(request):
    
    if request.user.is_authenticated:
        user_id = request.user.id
        home_folder_id = Folder.objects.get(user_id=user_id, parent_folder=None).id
        content= {"path": home_folder_id}
        return render(request, 'profile.html',content )
    else:
        return redirect('logIn')


"""
if user in home page parent id will be null
if user in folder page parent id will be previous folder id
"""
class CreateFolderView(APIView):
    
    def post(self, request, path, format=None):
        if request.user.is_authenticated and request.method == 'POST':
            user_id = request.user.id 
            folder_name = request.data.get('folderName')
            path_parts = request.path.split('/')
            parent_folder_id = path_parts[-2] # -1 adding-folder, -2 folder_id

            folder_data = {'name': folder_name, 'user_id': user_id, 'parent_folder': parent_folder_id}
            serializer = FolderSerializer(data=folder_data)

            if serializer.is_valid():
                serializer.save()
                return redirect('home', path=path) #return Response(serializer.data, status=status.HTTP_201_CREATED)
            return redirect('home', path=path) #return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        else:
            return redirect("logIn")


class CreateFileView(APIView):
    
    def post(self, request, path, format=None):   
        message = None

            
        if request.user.is_authenticated and request.method == 'POST':
            form = FileUploadForm(request.POST, request.FILES)
            user_id = request.user.id
            if form.is_valid():

                path_parts = request.path.split('/')
                parent_folder_id = path_parts[-2]

                file_name = request.FILES["file"].name 
                file_url = "encrypted_" + parent_folder_id+ "_" + file_name
                request.FILES["file"].name = file_url

                # aynı dosya isminden var mı kontrolü
                objects = File.objects.filter(user_id=user_id, parent_folder_id=parent_folder_id)
                if objects:   
                    for obj in objects:
                        if obj.name == file_name:
                            return redirect("deneme")

                file_type = request.FILES["file"].content_type
                file_size = request.FILES["file"].size
                
                encrypt_type = form.cleaned_data['encrypt_type']
                encryption_key = form.cleaned_data['encryption_key']
                file = form.cleaned_data['file']

                if encrypt_type == "DES" :
                     self.des_encrypt(request.FILES["file"],encryption_key, file_url)
                     key_save_to_file(user_id,encrypt_type,encryption_key,file_name,parent_folder_id)
                elif encrypt_type == "AES" :
                     self.aes_encrypt(request.FILES["file"],encryption_key, file_url)
                     key_save_to_file(user_id,encrypt_type,encryption_key,file_name,parent_folder_id)
                elif encrypt_type == "Blowfish" :
                     self.blowfish_encrypt(request.FILES["file"],encryption_key, file_url)
                     key_save_to_file(user_id,encrypt_type,encryption_key,file_name,parent_folder_id)
                else:
                    encrypt_type = "None"
                    file_url = parent_folder_id+ "_" + file_name
                    request.FILES["file"].name = file_url
                    self.save_nonencrypted_file(request.FILES["file"], file_url)

                file_data = {'name': file_name, 'file_type': file_type, 
                             'encrypt_type': encrypt_type, 'encryption_key': encryption_key, 'parent_folder': parent_folder_id, 
                             'user_id': int(request.user.id), 'size': file_size, 
                             'last_modified': timezone.now(), 'created': timezone.now(), 
                             'file': file,
                             'file_url': request.FILES["file"].name }
                # return render(request, 'deneme.html', context={'file_data': file_data})

                serializer = FileSerializer(data=file_data)
                if serializer.is_valid():
                    serializer.save()
                    return redirect('home', path=path)
                
                else:
                    error= serializer.errors
                    message= "serializer is not valid"
                    return render(request, 'deneme.html',context={'message': message, "error": error } )
            else: 
                error =   form.errors #
                message = "form is not valid"
                return render(request, 'deneme.html',context={'message': message, "error": error }  )
        else:
            return redirect("logIn")
        
    def save_nonencrypted_file(self, file, fileName):
        output_file_path = os.path.join(settings.MEDIA_ROOT, 'encrypted_files', fileName)
        with open(output_file_path, 'wb+') as f:
            for chunk in file.chunks():
                f.write(chunk)
                  
    def des_encrypt(self, input_file , key, fileName):
        byte_key = key.encode('utf-8')
        cipher = DES.new(byte_key, DES.MODE_ECB)
        # 'InMemoryUploadedFile' içeriğini oku
        plaintext = input_file.read()
        plaintext = pad(plaintext)
        ciphertext=cipher.encrypt(plaintext)
        
        output_file_path = os.path.join(settings.MEDIA_ROOT, 'encrypted_files', fileName)
        with open(output_file_path, 'wb') as file:
            file.write(ciphertext)

    def aes_encrypt(self, input_file , key, fileName):
        byte_key = key.encode('utf-8')
        # 'InMemoryUploadedFile' içeriğini oku
        plaintext = input_file.read()

        # Rastgele IV oluştur
        iv = os.urandom(16)

        # Cipher ve encryptor oluştur
        cipher = Cipher(algorithms.AES(byte_key), modes.CFB8(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        # Padding uygula
        padder = padding.PKCS7(algorithms.AES.block_size * 8).padder()
        padded_plaintext = padder.update(plaintext) + padder.finalize()

        # Şifrele
        ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

        output_file_path = os.path.join(settings.MEDIA_ROOT, 'encrypted_files', fileName)
        with open(output_file_path, 'wb') as file:
            file.write(iv + ciphertext)

    def blowfish_encrypt(self, input_file , key, fileName):
        byte_key = key.encode('utf-8')

        # 'InMemoryUploadedFile' içeriğini oku
        plaintext = input_file.read()

        # Blowfish'in blok boyutu 8 bayttır (64 bit)
        block_size = 8

        # Veriyi blok boyutuna uygun şekilde doldurun
        padder = padding.PKCS7(block_size * 8).padder()
        padded_plaintext = padder.update(plaintext) + padder.finalize()

        cipher = Cipher(algorithms.Blowfish(byte_key), modes.ECB(), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

        output_file_path = os.path.join(settings.MEDIA_ROOT, 'encrypted_files', fileName)
        with open(output_file_path, 'wb') as file:
            file.write(ciphertext)

class DownloadFileView(APIView): # otomatik çalışacak fonksiyonların isimleri get post put gibi isimler olmalı

        def get(self, request, path, id): # ???? post
            if request.user.is_authenticated and request.method == 'GET':

                path_parts = request.path.split('/')
                parent_folder_id = path_parts[-3]

                # hedef dosyanın veri tabanında bulunması
                user_id = request.user.id
                objects = File.objects.filter(user_id=user_id, parent_folder_id=parent_folder_id, id=id).first()
                if objects:   
                    file = {"name": objects.name,
                            'id': objects.id,
                            'file_type': objects.file_type,
                            'parent_folder': objects.parent_folder_id,
                            'user_id': objects.user_id,
                            "encrypt_type": objects.encrypt_type,
                            "size": objects.size,
                            "file_url": objects.file_url}
                    
                    file_path = os.path.join(settings.MEDIA_ROOT, 'encrypted_files', file["file_url"])
                    # key = self.get_encryptKey(file["user_id"], file["encrypt_type"],file["name"])
                   

                    if file["encrypt_type"] == "DES" :
                        key =rc4_file_decrypt(user_id,objects.name,objects.parent_folder_id)
                        plaintext = self.des_decrypt(file_path,key)
                        return render(request, "download_file.html", {"plaintext":(plaintext), "file_name":file["name"], "file_type":file["file_type"]})
                    elif file["encrypt_type"] == "AES" : 
                        key =rc4_file_decrypt(user_id,objects.name,objects.parent_folder_id)   
                        plaintext = self.aes_decrypt(file_path,key)
                        return render(request, "download_file.html", {"plaintext":(plaintext), "file_name":file["name"], "file_type":file["file_type"]})
                    elif file["encrypt_type"] == "Blowfish" :
                        key =rc4_file_decrypt(user_id,objects.name,objects.parent_folder_id) 
                        plaintext = self.blowfish_decrypt(file_path,key)
                        return render(request, "download_file.html", {"plaintext":(plaintext), "file_name":file["name"], "file_type":file["file_type"]})
                    else:
                        plaintext = self.get_nonencrypted_file(file_path)
                        return render(request, "download_file.html", {"plaintext":(plaintext), "file_name":file["name"], "file_type":file["file_type"]})
                else:
                    return render(request, "deneme.html", {"message":"file can not found in db"})

                # return redirect('home', path=path)
            else:   
                return redirect('logIn')
            
        def des_decrypt(self, file_path, key):
            cipher = DES.new(key, DES.MODE_ECB)

            with open(file_path, 'rb') as file:
              ciphertext = file.read()

            plaintext = cipher.decrypt(ciphertext)
            plaintext = unpad(plaintext)
            plaintext=plaintext.decode('utf-8')

            return plaintext 

        def aes_decrypt(self, file_path,key):
            with open(file_path, 'rb') as file:
                data = file.read()
            
            iv = data[:16]
            ciphertext = data[16:]   

            cipher = Cipher(algorithms.AES(key), modes.CFB8(iv), backend=default_backend())
            decryptor = cipher.decryptor()

            decrypted_text = decryptor.update(ciphertext) + decryptor.finalize()
            unpadder = padding.PKCS7(algorithms.AES.block_size * 8).unpadder()
            unpadded_plaintext = unpadder.update(decrypted_text) + unpadder.finalize()
            unpadded_plaintext=unpadded_plaintext.decode('utf-8')
            return unpadded_plaintext

        def blowfish_decrypt(self, file_path,key):
            with open(file_path, 'rb') as file:
                ciphertext = file.read()

            cipher = Cipher(algorithms.Blowfish(key), modes.ECB(), backend=default_backend())
            decryptor = cipher.decryptor()
            padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

            unpadder = padding.PKCS7(8 * 8).unpadder()
            plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

            plaintext=plaintext.decode('utf-8')

            return plaintext

        def get_nonencrypted_file(self, file_path):
            plaintext = ""
            with open(file_path, 'rb') as file:
                plaintext = file.read()
            plaintext = plaintext.decode('utf-8')
            return plaintext
        
        def get_encryptKey(self, user_id, encrypt_type,fileName): 
            file_csv = str(user_id) + "_keys.csv"
            rc4_file_path = os.path.join(settings.MEDIA_ROOT, 'rc4_files', file_csv)


def pad(data):
    # Veriyi 8 byte'lık bloklara uygun hale getir
    length = 8 - (len(data) % 8)
    return data + bytes([length] * length)

def unpad(data):
    # Veriden çıkartılan dolguyu kaldır
    return data[:-data[-1]]

def key_save_to_file(user_id,encrypt_type,encryption_key,fileName,parent_folder_id) :
    fileName=parent_folder_id + "/" + fileName

    bilgiler = [str(user_id), encrypt_type, encryption_key, fileName]
    key = b'SecretKey123'
    ciphertext=encrypt_csv_with_rc4(key,bilgiler) 
    # Şifrelenmiş veriyi stringe çevirme
    encrypted_result_str =[str(item) for item in ciphertext] 

    file_csv = str(user_id) + "_keys.csv"
    output_file_path = os.path.join(settings.MEDIA_ROOT, 'rc4_files', file_csv)

    # CSVs dosyasına bilgileri yazma
    with open(output_file_path, "a", newline='') as dosya:
        # CSV dosyasına yazmak için bir yazıcı oluştur
        csv_writer = csv.writer(dosya)
        # Veriyi CSV dosyasına yaz
        csv_writer.writerow(encrypted_result_str)

def rc4_file_decrypt(userId,fileName,parentId):
    filePath = "website_app/media/rc4_files/"+ str(userId) + "_keys.csv"
    fileName = str(parentId) + "/" + fileName
    # CSV verilerini dosyadan oku
    data_list = []

    with open(filePath, 'r') as csvfile:
        csv_reader = csv.reader(csvfile)
        
        for row in csv_reader:
            data_list.append(row)
    
    key = b'SecretKey123'

    decrypted_result = decrypt_csv_with_rc4(key, data_list)
    e_key=None

    for row in decrypted_result:
        if(fileName==row[3]):
            e_key = row[2]
    e_key = e_key.encode('utf-8') 

    return e_key

def rc4_encrypt(key, plaintext):
    cipher = ARC4.new(key)
    ciphertext = cipher.encrypt(plaintext)
    return ciphertext

def encrypt_csv_with_rc4(key, csv_data):
     # CSV verisini RC4 kullanarak şifrele
       # Veriyi RC4 kullanarak şifrele ve base64 ile stringe çevir
    encrypted_data = [base64.b64encode(rc4_encrypt(key, data.encode())).decode() for data in csv_data]
    
    return encrypted_data

def rc4_decrypt(key, ciphertext):
    cipher = ARC4.new(key)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext

def decrypt_csv_with_rc4(key, encrypted_data):
    plaintext_data_csv=[]
   
    for row in encrypted_data:
        # Veriyi base64'ten çöz ve RC4 kullanarak çöz
        decrypted_data_row = [rc4_decrypt(key, base64.b64decode(data)) for data in row]
        # Sonuçları utf-8'e çevir
        decrypted_row = [data.decode('utf-8') for data in decrypted_data_row]
        plaintext_data_csv.append(decrypted_row)

    return plaintext_data_csv



def deneme(request):
    content = {}
    # files= getFiles(request.user.id, 2)
    # content.update({"files":files})
    # folders = getFolders(request.user.id, 2)
    # content.update({"folders":folders, "message":""})

    user_id = request.user.id
    path_parts = request.path.split('/')
    parent_folder_id = path_parts[-2]

    objects = File.objects.filter(user_id=str(user_id), parent_folder_id=2, id=22)
    content.update({"file":objects})

    return render(request, 'deneme.html',content )


# örnek fonksiyon Bu fonksiyon, Django'nun geliştirme sunucusu üzerinden medya dosyalarını servis etmenizi sağlar. 
def media_serve(request, path):
    media_root = settings.MEDIA_ROOT
    file_path = os.path.join(media_root, path)
    return FileResponse(open(file_path, 'rb'))


