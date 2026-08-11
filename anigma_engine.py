# DEVELOPER: Amir Mehdi Basavand (امیر مهدی بساوند)
# ====================================================================================
# PROJECT: ANIGMA MODERN | Core Engine Module
# ====================================================================================

import base64
import hashlib
import secrets
import string
import os
import sys
import zlib
import urllib.request
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes

CURRENT_VERSION = "15.8"
PBKDF2_ITERATIONS = 200_000
SALT_SIZE = 16

VERSION_URL = "https://raw.githubusercontent.com/amirjkkjhk-ux/Anigma-Modern/main/version.txt.txt"
CHECKSUMS_URL = "https://raw.githubusercontent.com/amirjkkjhk-ux/Anigma-Modern/main/checksums.txt"

def derive_key(password: str, salt: bytes) -> bytes:
    """اشتقاق امن کلید AES-256 از رمز عبور با PBKDF2."""
    return PBKDF2(password.encode("utf-8"), salt, dkLen=32, count=PBKDF2_ITERATIONS)

def fetch_expected_hash(filename):
    """هش SHA-256 رسمی یک فایل را از سرور دریافت می‌کند."""
    try:
        req = urllib.request.Request(CHECKSUMS_URL, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=10) as resp:
            content = resp.read().decode('utf-8', errors='ignore')
        for line in content.splitlines():
            parts = line.strip().split()
            if len(parts) >= 2 and parts[0] == filename:
                return parts[1].lower()
    except Exception:
        pass
    return None

def generate_random_key_string():
    """تولید یک کلید تصادفی با امنیت بالا."""
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
    return "".join(secrets.choice(alphabet) for _ in range(16))

def encrypt_text(txt: str, secret_key: str) -> str:
    """رمزگذاری متن با استفاده از AES-GCM."""
    salt = get_random_bytes(SALT_SIZE)
    key = derive_key(secret_key, salt)
    cipher = AES.new(key, AES.MODE_GCM)
    ctx, tag = cipher.encrypt_and_digest(txt.encode('utf-8'))
    # فرمت خروجی: salt + nonce + tag + ciphertext
    result = base64.urlsafe_b64encode(salt + cipher.nonce + tag + ctx).decode('utf-8')
    return result

def decrypt_text(ctx_base64: str, secret_key: str) -> str:
    """رمزگشایی متن با استفاده از AES-GCM."""
    r = base64.urlsafe_b64decode(ctx_base64.encode('utf-8'))
    salt, nonce, tag, encrypted = r[:16], r[16:32], r[32:48], r[48:]
    key = derive_key(secret_key, salt)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(encrypted, tag).decode('utf-8')
