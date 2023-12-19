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

from pymongo import MongoClient
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .models import *
from .serializers import FolderSerializer, FileSerializer


import os
import json
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
                     "encrypt_type": file.encrypt_type,
                     "size": file.size,
                     "last_modified": file.last_modified,
                     "created": file.created,
                     "file": file.file}
        files.append(file_dict)
    return files

def deleteFile():
    pass
 
def home(request, path):
    if request.user.is_authenticated:
        content= {"path": path}

        path_parts = request.path.split('/')
        parent_folder_id = path_parts[-2]
        folders = getFolders(request.user.id, parent_folder_id)
        content.update({"folders":folders})

        files = getFiles(request.user.id, parent_folder_id)
        content.update({"files":files})

        form = FileUploadForm()
        content.update({"uploadForm":form})
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
            if form.is_valid():

                file_name = request.FILES["file"].name
                file_type = request.FILES["file"].content_type


                encrypt_type = form.cleaned_data['encrypt_type']
                encryption_key = form.cleaned_data['encryption_key']
                if encrypt_type == "DES" :
                     self.des_encrypt(request.FILES["file"],encryption_key, file_name)
                elif encrypt_type == "AES" :
                     self.aes_encrypt(request.FILES["file"],encryption_key, file_name)
                elif encrypt_type == "Blowfish" :
                     self.blowfish_encrypt(request.FILES["file"],encryption_key, file_name)
                else:
                    encrypt_type = "None"

                path_parts = request.path.split('/')
                parent_folder = path_parts[-2]

                file_size = request.FILES["file"].size


                file_data = {'name': file_name, 'file_type': file_type, 
                             'encrypt_type': encrypt_type, 'encryption_key': encryption_key, 'parent_folder': parent_folder, 
                             'user_id': request.user.id, 'size': file_size, 
                             'last_modified': timezone.now(), 'created': timezone.now(), 
                             'file': request.FILES["file"]}
                serializer = FileSerializer(data=file_data)
                if serializer.is_valid():
                    serializer.save()
                    
                    return redirect('home', path=path)
                else:

                    message= serializer.errors

                    return redirect('deneme', message=message)
            else: 
                message =  "Form is not valid"  # form.errors #

                return redirect('deneme', message=message) 
        else:
            return redirect("logIn")
    
    def des_encrypt(self, input_file , key, fileName):
        byte_key = key.encode('utf-8')

        cipher = DES.new(byte_key, DES.MODE_ECB)

        # 'InMemoryUploadedFile' içeriğini oku
        plaintext = input_file.read()

        plaintext = pad(plaintext)
        ciphertext=cipher.encrypt(plaintext)

        output_file_path ="encrypted_" +  fileName
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

        output_file_path ="encrypted_" +  fileName
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

        output_file_path ="encrypted_" +  fileName
        with open(output_file_path, 'wb') as file:
            file.write(ciphertext)

    

def deneme(request, message):
    folders = getFolders(request.user.id, 2)
    content = {"folders":folders, "message":message}
    return render(request, 'deneme.html',content )


#Bu fonksiyon, Django'nun geliştirme sunucusu üzerinden medya dosyalarını servis etmenizi sağlar. 
def media_serve(request, path):
    media_root = settings.MEDIA_ROOT
    file_path = os.path.join(media_root, path)
    return FileResponse(open(file_path, 'rb'))


def pad(data):
    # Veriyi 8 byte'lık bloklara uygun hale getir
    length = 8 - (len(data) % 8)
    return data + bytes([length] * length)

def unpad(data):
    # Veriden çıkartılan dolguyu kaldır
    return data[:-data[-1]]