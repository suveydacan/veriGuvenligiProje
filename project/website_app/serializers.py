from rest_framework import serializers
from .models import Folder, File

class FolderSerializer(serializers.ModelSerializer):
    files = serializers.PrimaryKeyRelatedField(many=True, read_only=True) 
    class Meta:
        model = Folder
        fields = ['id', 'name', 'type', 'parent_folder', 'user_id', 'files']


class FileSerializer(serializers.ModelSerializer):
    class Meta:
        model = File
        fields = ['id', 'name', 'type', 'file_type', 'encrypt_type', 'parent_folder', 'user_id', 'size', 'last_modified', 'created', 'file']



    


