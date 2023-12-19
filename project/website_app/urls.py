from django.urls import include, path, re_path
from . import views
from .views import CreateFolderView, CreateFileView
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
    # url(r'^prefix/(?P<path>[a-zA-Z\/]*)/$', your_view),
    re_path(r'^home/(?P<path>[\d/]+)/$', views.home, name='home'),
    path('home/subfolder/<path:path>/<int:id>/', views.openSubFolder, name='subfolder'),
    # path("home/<int:id>/adding-folder", CreateFolderView.as_view(), name="adding-folder"),
    re_path(r'^home/(?P<path>[\d/]+)/adding-folder', CreateFolderView.as_view(), name="adding-folder"),
    path("home/<path:path>/<int:id>/delete", views.deleteFolder, name="deleteFolder"),
    # path("home/<path:path>/upload-file", views.upload_file, name="upload-file"),
    path("home/<path:path>/upload-file", CreateFileView.as_view(), name="upload-file"),


    path('media/<path>', views.media_serve, name='media-serve'),
    path("deneme/<str:message>", views.deneme, name="deneme"),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)




