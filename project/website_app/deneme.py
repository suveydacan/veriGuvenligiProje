

import os
from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from Crypto.Cipher import ARC4
import json

# from pymongo import MongoClient
from django.db import models


import os
import csv
from datetime import datetime, timedelta
from django.utils import timezone
import re
import random
from collections import defaultdict
import logging
from pathlib import Path



class File(models.Model):
    name = models.CharField(max_length=255)
    type = models.CharField(max_length=10, default='file')
    file_type = models.CharField(max_length=100, default=None)
    encrypt_type = models.CharField(max_length=20, default=None)
    encryption_key = models.CharField(max_length=256, default=None)
    parent_folder = models.ForeignKey(Folder, related_name='files', on_delete=models.CASCADE)
    user_id = models.CharField(max_length=255)
    size = models.BigIntegerField()
    last_modified = models.DateTimeField(auto_now=True)
    created = models.DateTimeField(auto_now_add=True)
    file_url = models.CharField(max_length=512)
    file = models.FileField(upload_to='file', storage=grid_fs_storage, null=True) # upload_to=func_to_declare_where_save_it
    


user_id = 5
parent_folder_id = 2
objects = File.objects.filter(user_id=str(user_id), parent_folder_id=parent_folder_id, id=22)
print(objects)