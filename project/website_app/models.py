# models.py
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager
from django.db import models
from django.conf import settings

from djongo.storage import GridFSStorage
grid_fs_storage = GridFSStorage(collection='myfiles', base_url='./myfiles/')

class Folder(models.Model):
    name = models.CharField(max_length=255)
    type = models.CharField(max_length=10, default='folder')
    parent_folder = models.ForeignKey('self', null=True, blank=True, on_delete=models.CASCADE)
    user_id = models.CharField(max_length=255)

class FileRC4(models.Model):
    user_id = models.CharField(max_length=255)
    rc4_key = models.CharField(max_length=256)
    active = models.BooleanField(default=True)

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



    
    # path = models.CharField(max_length=255)



# eğer null ve blank girilmemişse false default değer olarak atanır
    
"""
file daki parent folder daki related name özelliği ile 
folder = Folder.objects.get(pk=1)
files_in_folder = folder.files.all()
yapılabiliyor

    # class FolderItems(models.Model):
    #     folder = models.ForeignKey('Folder', on_delete=models.CASCADE)

    # class FileItems(models.Model):
    #     file = models.ForeignKey('File', null=True, blank=True, on_delete=models.CASCADE)

"""

"""
from django.core.files.storage import Storage
from gridfs_storage.storage import GridFSStorage

class WebsiteAppFileStorage(GridFSStorage):
    def __init__(self, **kwargs):
        kwargs['location'] = 'website_app_file'
        super().__init__(**kwargs)

website_app_file_storage = WebsiteAppFileStorage()
"""