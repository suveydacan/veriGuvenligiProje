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

from .forms import SignUpForm

from pymongo import MongoClient


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



    
def home(request):
    content= {}
    return render(request, 'home.html',content )

def logIn(request):
    context = {}
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')
        username = User.objects.get(email=email).username
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            return redirect('profile')   
        else:
            context.update({"error":"user none"})

    return render(request, 'login.html', context)

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
    
def profile(request):
    content= {}
    username = None
    if request.user.is_authenticated:
        username = request.user.username

    content.update({"username":username})

    return render(request, 'profile.html',content )

