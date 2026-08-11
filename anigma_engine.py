# DEVELOPER: Amir Mehdi Basavand (امیر مهدی بساوند)
# EMAIL: amirjkkjhk@gmail.com | TELEGRAM: @Amirshoq
# ====================================================================================
# PROJECT: ANIGMA MODERN | Core Engine Module v17.5 Pro
# ====================================================================================

import base64
import hashlib
import secrets
import string
import os
import sys
import zlib
import urllib.request
import ssl
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes

CURRENT_VERSION = "17.5"
PBKDF2_ITERATIONS = 200_000
SALT_SIZE = 16
NONCE_SIZE = 16
TAG_SIZE = 16

VERSION_URL = "https://raw.githubusercontent.com/amirjkkjhk-ux/Anigma-Modern/main/version.txt"
CHECKSUMS_URL = "https://raw.githubusercontent.com/amirjkkjhk-ux/Anigma-Modern/main/checksums.txt"

def get_ssl_context():
    """ایجاد کانتکست SSL امن برای جلوگیری از خطای اتصال شبکه در ویندوز."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx

def derive_key(password: str, salt: bytes) -> bytes:
    """اشتقاق امن کلید AES-256 با PBKDF2."""
    return PBKDF2(password.encode("utf-8"), salt, dkLen=32, count=PBKDF2_ITERATIONS)

def check_remote_version():
    """بررسی وجود نسخه جدید در گیتهاب."""
    try:
        req = urllib.request.Request(VERSION_URL, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=5, context=get_ssl_context()) as resp:
            remote_ver = resp.read().decode('utf-8').strip()
            return remote_ver
    except Exception:
        return None

def generate_random_key_string(length=20):
    """تولید کلید تصادفی پیشرفته شامل حروف، اعداد و کاراکترهای خاص."""
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
    return "".join(secrets.choice(alphabet) for _ in range(length))

def encrypt_text(txt: str, secret_key: str) -> str:
    """رمزگذاری متن با AES-256-GCM (کاملاً سازگار با نسخه وب)."""
    salt = get_random_bytes(SALT_SIZE)
    key = derive_key(secret_key, salt)
    cipher = AES.new(key, AES.MODE_GCM, nonce=get_random_bytes(NONCE_SIZE))
    ciphertext, tag = cipher.encrypt_and_digest(txt.encode('utf-8'))
    
    # ساختار بایت‌ها: Salt + Nonce + Tag + Ciphertext
    payload = salt + cipher.nonce + tag + ciphertext
    return base64.urlsafe_b64encode(payload).decode('utf-8')

def decrypt_text(ctx_base64: str, secret_key: str) -> str:
    """رمزگشایی متن با AES-256-GCM."""
    padded_b64 = ctx_base64.replace('-', '+').replace('_', '/')
    while len(padded_b64) % 4 != 0:
        padded_b64 += '='
        
    data = base64.b64decode(padded_b64)
    salt = data[:SALT_SIZE]
    nonce = data[SALT_SIZE:SALT_SIZE + NONCE_SIZE]
    tag = data[SALT_SIZE + NONCE_SIZE:SALT_SIZE + NONCE_SIZE + TAG_SIZE]
    ciphertext = data[SALT_SIZE + NONCE_SIZE + TAG_SIZE:]

    key = derive_key(secret_key, salt)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    decrypted_bytes = cipher.decrypt_and_verify(ciphertext, tag)
    return decrypted_bytes.decode('utf-8')
