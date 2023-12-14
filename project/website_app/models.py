# models.py
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager
from django.db import models


class Folder(models.Model):
    name = models.CharField(max_length=255)
    type = models.CharField(max_length=10, default='folder')
    parent_folder = models.ForeignKey('self', null=True, blank=True, on_delete=models.CASCADE)
    user_id = models.CharField(max_length=255)

    class FolderItems(models.Model):
        folder = models.ForeignKey('Folder', on_delete=models.CASCADE)

    class FileItems(models.Model):
        file = models.ForeignKey('File', null=True, blank=True, on_delete=models.CASCADE)



class File(models.Model):
    name = models.CharField(max_length=255)
    type = models.CharField(max_length=10, default='file')
    encrypt_type = models.CharField(max_length=20, default='none')
    parent_folder = models.ForeignKey(Folder, related_name='files', on_delete=models.CASCADE)
    user_id = models.CharField(max_length=255)
    size = models.BigIntegerField()
    last_modified = models.DateTimeField(auto_now=True)
    created = models.DateTimeField(auto_now_add=True)
    # path = models.CharField(max_length=255)



# eğer null ve blank girilmemişse false default değer olarak atanır
    
"""
file daki parent folder daki related name özelliği ile 
folder = Folder.objects.get(pk=1)
files_in_folder = folder.files.all()
yapılabiliyor
"""