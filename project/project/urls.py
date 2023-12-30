
from django.contrib import admin
from django.urls import path, include
from django.contrib.auth import views as auth_views #import this
from django.conf import settings
from django.conf.urls.static import static
from website_app import views as website_app_views

urlpatterns = [
    path("", include('website_app.urls')),
    # path("admin/", admin.site.urls),
    path("website_app/", include('website_app.urls')),

]
