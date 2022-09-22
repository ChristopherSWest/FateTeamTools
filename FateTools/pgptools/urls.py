from django.urls import path
from . import views

urlpatterns = [
    path("", views.index, name="pgptools"),
    path("listKeys", views.list_keys, name="listKeys")
]