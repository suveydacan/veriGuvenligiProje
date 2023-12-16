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

from .forms import SignUpForm

from pymongo import MongoClient
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .models import *
from .serializers import FolderSerializer


import os
import json
from datetime import datetime, timedelta
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

            return redirect('home', id=home_folder_id) 
        else:
            context.update({"error":"user none"})

    return render(request, 'login.html', context)

def home(request, id):
    content= {"home":"home", "id":id}
    if request.user.is_authenticated:
        return render(request, 'home.html',content )
    else:   
        return redirect('logIn')


def profile(request):
    content= {}
    username = None
    if request.user.is_authenticated:
        return render(request, 'profile.html',content )
    else:
        return redirect('logIn')


def addFolder(request):
    requested_path = request.path
    folder_name = request.POST['folderName']
    path_parts = request.path.split('/')
    content = {"folder_names": folder_name, 
               "requested_path": requested_path,
                "path_parts": path_parts,
               }
    return render(request, 'home.html',context = content )
    # return redirect('home') 

"""
if user in home page parent id will be null
if user in folder page parent id will be previous folder id
"""
class CreateFolderView(APIView):
    
    def post(self, request, id, format=None):
        if request.user.is_authenticated and request.method == 'POST':
            user_id = request.user.id 
            folder_name = request.data.get('folderName')
            path_parts = request.path.split('/')
            parent_folder_id = path_parts[-2] # -1 adding-folder, -2 folder_id

            folder_data = {'name': folder_name, 'user_id': user_id, 'parent_folder': parent_folder_id}
            serializer = FolderSerializer(data=folder_data)

            user_id = request.user.id
            home_folder_id = Folder.objects.get(user_id=user_id, parent_folder=None).id

            if serializer.is_valid():
                serializer.save()
                return redirect('home', id=home_folder_id) #return Response(serializer.data, status=status.HTTP_201_CREATED)
            return redirect('home', id=home_folder_id) #return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        else:
            return redirect("logIn")
        


