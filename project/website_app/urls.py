from django.urls import include, path, re_path
from . import views
from .views import CreateFolderView, CreateFileView, DownloadFileView
from django.contrib import admin
from django.conf import settings
from django.conf.urls.static import static
from django.apps import apps


urlpatterns = [

    path("", views.index, name="index"),
    
    path("login/", views.logIn, name="login"),
    path("logout/", views.log_out, name="logout"),
    path("signUp/", views.signUp, name="signUp"),
    path("profile/", views.profile, name="profile"),

    # path("home/<int:id>", views.home, name="home"),
    re_path(r'^home/(?P<path>[\d/]+)/$', views.home, name='home'),
    path('home/subfolder/<path:path>/<int:id>/', views.openSubFolder, name='subfolder'),
    re_path(r'^home/(?P<path>[\d/]+)/adding-folder', CreateFolderView.as_view(), name="adding-folder"),
    path("home/<path:path>/<int:id>/deleteFolder", views.deleteFolder, name="deleteFolder"),

    path("home/<path:path>/upload-file", CreateFileView.as_view(), name="upload-file"),
    path("home/<path:path>/<int:id>/deleteFile", views.deleteFile, name="deleteFile"),
    path("home/<path:path>/<int:id>/downloadFile", DownloadFileView.as_view(), name="downloadFile"),
    path("home/<path:path>/<int:id>/carryFile", views.carryFile, name="carryFile"),


    # path('media/<path>', views.media_serve, name='media-serve'),
    path("deneme/", views.deneme, name="deneme"),
]

# if settings.DEBUG:
urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
# urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
