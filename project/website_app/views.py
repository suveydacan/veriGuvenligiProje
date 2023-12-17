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

from pymongo import MongoClient
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .models import *
from .serializers import FolderSerializer


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
        

def upload_file(request, path):
    if request.user.is_authenticated and request.method == 'POST':
        form = SignUpForm(request.POST)
        if form.is_valid():
            file_name = form.cleaned_data['name']
            file_type = form.cleaned_data['file_type']
            encrypt_type = form.cleaned_data['encrypt_type']
            if encrypt_type == "Hiçbiri":
                encrypt_type = None
            path_parts = request.path.split('/')
            parent_folder = path_parts[-2]

            file_size = form.cleaned_data['file'].size

            new_file = File(
                name=file_name,
                file_type=file_type,
                parent_folder=parent_folder,
                encrypt_type=encrypt_type,
                user_id=request.user.id,  
                size=file_size,
                last_modified=timezone.now(),
                created=timezone.now(),
                file=form.cleaned_data['file']
            )
            new_file.save()

        return redirect('home', path=path)  

    return redirect("logIn")



def deneme(request):
    folders = getFolders(request.user.id, 2)
    content = {"folders":folders}
    return render(request, 'deneme.html',content )