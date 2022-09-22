from django.shortcuts import render
from django.http import HttpResponse, JsonResponse
import gnupg
import json

# Create your views here.
def index(request):
    return render(request, "pgptools/index.html")

def list_keys(request):
    gpg = gnupg.GPG()
    public_keys = gpg.list_keys()
    print(public_keys)
    return JsonResponse({
        "keys_list": str(public_keys)
    })