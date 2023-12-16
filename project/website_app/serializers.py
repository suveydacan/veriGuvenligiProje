from rest_framework import serializers
from .models import Folder

class FolderSerializer(serializers.ModelSerializer):

    class Meta:
        model = Folder
        fields = ['id', 'name', 'type', 'parent_folder', 'user_id']



    # files = serializers.PrimaryKeyRelatedField(many=True, read_only=True) 