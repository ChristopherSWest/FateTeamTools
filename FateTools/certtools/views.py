from hmac import digest_size
import json
from ssl import VerifyFlags
from statistics import median_grouped
from django.shortcuts import render
from django.http import HttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_exempt
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.asymmetric import padding

from  cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
import base64

#add colons to sha hexes
def add_colon(hex):
    hex_list = list(hex)
    
    count = 0
    updated_hex = ""
    for digit in hex:
        count += 1
        updated_hex += digit
        if (count % 2 == 0 and count < len(hex)):
            updated_hex += ':'
    return updated_hex


# Create your views here.
def index(request):
    return render(request, "certtools/index.html")

@csrf_exempt
def certInfo(request):
    json_data = json.loads(request.body)
    cert_data = json_data["certString"]
    
    try:
        # Decode the certficate from the SAML
        base64_bytes = cert_data.encode('utf-8')
        decoded_data = base64.decodebytes(base64_bytes)
        cert = x509.load_der_x509_certificate(decoded_data)
    except:
        base64_bytes = cert_data.encode('utf-8')
        cert = x509.load_pem_x509_certificate(base64_bytes)
    

    # Pull information from the certificate and get it ready for the response
    serial = hex(cert.serial_number)
    public_key = cert.public_key()
    public_key_pem = public_key.public_bytes(Encoding.PEM, PublicFormat.PKCS1).decode('utf-8')
    cert_PEM = cert.public_bytes(Encoding.PEM).decode('utf-8')
    fingerprint = {
        "SHA256": add_colon(str(cert.fingerprint(hashes.SHA256()).hex())),
        "SHA1": add_colon(str(cert.fingerprint(hashes.SHA1()).hex()))
    }
    

    return JsonResponse({
        "serial": str(serial),
        "fingerprint": fingerprint,
        "notBefore": str(cert.not_valid_before),
        "notAfter": str(cert.not_valid_after),
        "subject": str(cert.subject),
        "publicKey": str(public_key_pem),
        "certPEM": str(cert_PEM)
    })

@csrf_exempt
def checkSignature(request):
    json_data = json.loads(request.body)
    signature_input = json_data["signatureInput"]
    cert_data = json_data["certPEM"]
    
    #Decode the signature from a SAML
    base64_bytes = signature_input.encode('utf-8')
    signature_bytes = base64.decodebytes(base64_bytes)
    print(base64_bytes)
    print(signature_bytes)
    #Decode PEM cert
    base64_bytes = cert_data.encode('utf-8')
    #cert_data = base64.decodebytes(base64_bytes)
    
    cert = x509.load_der_x509_certificate(base64_bytes)
    public_key = cert.public_key()
    public_key.verify(cert.signature, cert.tbs_certificate_bytes, padding.PKCS1v15(), cert.signature_hash_algorithm)


    
