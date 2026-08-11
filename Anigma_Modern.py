# DEVELOPER: Amir Mehdi Basavand (امیر مهدی بساوند)
# EMAIL: amirjkkjhk@gmail.com
# TELEGRAM ID: @Amirshoq
# ====================================================================================
# PROJECT: ANIGMA MODERN | VERSION: 15.8 (Fixed Memory, Progress Bar & Secure Random)
# ====================================================================================

import tkinter as tk
from tkinter import messagebox, ttk, filedialog, simpledialog
from tkinterdnd2 import TkinterDnD, DND_FILES 
import base64
import hashlib
import secrets  # استفاده از ماژول امنیتی به جای random
import string
import os
import sys
import zlib
import threading
import json
import subprocess
from datetime import datetime
import urllib.request 
import ssl 
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes

CONFIG_FILE = "config.json"
CURRENT_VERSION = "15.8"
PBKDF2_ITERATIONS = 200_000
SALT_SIZE = 16

VERSION_URL = "https://raw.githubusercontent.com/amirjkkjhk-ux/Anigma-Modern/main/version.txt.txt"
CHECKSUMS_URL = "https://raw.githubusercontent.com/amirjkkjhk-ux/Anigma-Modern/main/checksums.txt"

LANGUAGES = {
    "fa": {
        "title": f"آنیگما مدرن v{CURRENT_VERSION}",
        "protocol": "پروتکل: AES-256 + Zlib",
        "tab_text": "قفل‌گذاری متنی",
        "tab_file": "قفل‌گذاری فایل",
        "input_label": "۱. متن عادی یا رمزگذاری شده را وارد کنید:",
        "paste_btn": "جاگذاری متن کپی شده (PASTE)",
        "key_label": "کلید امنیتی مشترک (SECRET KEY):",
        "key_empty": "کلید: خالی",
        "key_weak": "ضعیف",
        "key_good": "متوسط",
        "key_strong": "قوی",
        "key_military": "فوق امنیتی (نظامی)",
        "show_key": "نمایش رمز",
        "copy_key": "کپی رمز",
        "rand_key": "تولید کلید تصادفی",
        "key_manager": "مدیریت کلیدها",
        "encrypt": "رمزگذاری متنی",
        "decrypt": "رمزگشایی متنی",
        "clear": "پاکسازی فرم",
        "output_label": "۲. خروجی متنی سیستم:",
        "copy_output": "کپی کردن متن خروجی (COPY)",
        "file_section": "بخش فایل (فایل را انتخاب کنید یا اینجا رها کنید):",
        "select_file_btn": "انتخاب فایل از کامپیوتر",
        "enc_file_btn": "رمزگذاری فایل",
        "dec_file_btn": "رمزگشایی فایل",
        "log_section": "تاریخچه عملیات سیستم (Logs):",
        "log_active": "تاریخچه: فعال",
        "log_inactive": "تاریخچه: غیرفعال",
        "log_clear_btn": "حذف تاریخچه",
        "status_online": "وضعیت: آنلاین | موتور متنی و فایلی AES فعال",
        "status_copied": "وضعیت: خروجی کپی شد! [OK]",
        "status_key_copied": "وضعیت: کلید کپی شد!",
        "status_pasted": "وضعیت: داده‌ها جاگذاری شدند! [OK]",
        "status_paste_failed": "وضعیت: خطا در جاگذاری! [ERROR]",
        "status_encrypted": "وضعیت: رمزگذاری متن موفق!",
        "status_decrypted": "وضعیت: رمزگشایی متن موفق!",
        "status_cleared": "وضعیت: ترمینال پاکسازی شد",
        "status_no_copy": "وضعیت: چیزی برای کپی نیست! [FAIL]",
        "status_file_enc": "وضعیت: فایل با موفقیت قفل شد!",
        "status_file_dec": "وضعیت: فایل با موفقیت باز شد!",
        "warning_empty": "متن ورودی یا کلید امنیتی خالی است!",
        "warning_no_file": "لطفاً ابتدا یک فایل انتخاب کنید و رمز را وارد کنید!",
        "error_decrypt": "رمز عبور اشتباه است یا پیام دستکاری شده!",
        "menu_help": "راهنمای کامل و شناسنامه سازنده",
        "menu_update": "بررسی آپدیت آنلاین",
        "processing": "وضعیت: در حال پردازش فایل... لطفاً صبر کنید [WAIT]"
    },
    "en": {
        "title": f"ANIGMA MODERN v{CURRENT_VERSION}",
        "protocol": "PROTOCOL: AES-256 + Zlib ENGINE",
        "tab_text": "Text Encryption",
        "tab_file": "File Encryption",
        "input_label": "1. Enter Plain text or Cipher text:",
        "paste_btn": "PASTE COPIED TEXT",
        "key_label": "Global SECRET KEY:",
        "key_empty": "KEY: EMPTY",
        "key_weak": "WEAK",
        "key_good": "GOOD",
        "key_strong": "STRONG",
        "key_military": "MILITARY GRADE",
        "show_key": "Show Key",
        "copy_key": "Copy Key",
        "rand_key": "Generate Random Key",
        "key_manager": "Key Manager",
        "encrypt": "ENCRYPT TEXT",
        "decrypt": "DECRYPT TEXT",
        "clear": "CLEAR FORM",
        "output_label": "2. System Text Output:",
        "copy_output": "COPY OUTPUT TEXT",
        "file_section": "File Section (Select or Drag & Drop File here):",
        "select_file_btn": "Select File from PC",
        "enc_file_btn": "Encrypt File",
        "dec_file_btn": "Decrypt File",
        "log_section": "System Operation Logs:",
        "log_active": "Logs: Active",
        "log_inactive": "Logs: Inactive",
        "log_clear_btn": "Clear Logs",
        "status_online": "STATUS: SYSTEM ONLINE (AES ENGINE)",
        "status_copied": "STATUS: OUTPUT COPIED! [OK]",
        "status_key_copied": "STATUS: KEY COPIED!",
        "status_pasted": "STATUS: DATA PASTED! [OK]",
        "status_paste_failed": "STATUS: PASTE FAILED! [ERROR]",
        "status_encrypted": "STATUS: TEXT ENCRYPTED SUCCESS!",
        "status_decrypted": "STATUS: TEXT DECRYPTED SUCCESS!",
        "status_cleared": "STATUS: TERMINAL CLEARED",
        "status_no_copy": "STATUS: NOTHING TO COPY! [FAIL]",
        "status_file_enc": "STATUS: FILE ENCRYPTED SUCCESS!",
        "status_file_dec": "STATUS: FILE DECRYPTED SUCCESS!",
        "warning_empty": "Input text or secret key is empty!",
        "warning_no_file": "Please select a file and enter a secret key first!",
        "error_decrypt": "Wrong key or corrupted data!",
        "menu_help": "Full User Guide & Developer info",
        "menu_update": "Check for Updates",
        "processing": "STATUS: Processing file... Please wait [WAIT]"
    }
}

THEMES = {
    "night": {
        "bg": "#050a12", "card": "#0b121f", "input": "#0d1726", "text": "#ffffff",
        "accent": "#00ffcc", "btn_primary": "#ff0055", "btn_secondary": "#341f97", "muted": "#8a9fc4"
    },
    "hacker": {
        "bg": "#000000", "card": "#0a0a0a", "input": "#0f0f0f", "text": "#33ff33",
        "accent": "#33ff33", "btn_primary": "#118811", "btn_secondary": "#222222", "muted": "#00aa00"
    },
    "light": {
        "bg": "#f1f2f6", "card": "#ffffff", "input": "#e4e7eb", "text": "#2f3542",
        "accent": "#2f3542", "btn_primary": "#ff4757", "btn_secondary": "#747d8c", "muted": "#57606f"
    }
}

current_lang = "fa"
current_theme = "night"
selected_file_path = ""
logs_enabled = True
saved_keys = {}          # کلیدهای رمزگشایی‌شده - فقط بعد از باز شدن قفل با رمز اصلی پر می‌شود
saved_keys_raw_blob = None  # بلوک رمزگذاری‌شده‌ی خام همان‌طور که در config.json ذخیره می‌شود
kdf_salt = None           # bytes - salt ثابت برای اشتقاق کلید از رمز اصلی
kdf_verifier = None       # هش کلید مشتق‌شده، فقط برای تایید صحت رمز اصلی (بدون افشای خود رمز)
master_key = None         # کلید مشتق‌شده از رمز اصلی - فقط در حافظه (RAM) و فقط طی همین نشست

def derive_key(password: str, salt: bytes) -> bytes:
    """اشتقاق امن کلید AES-256 از رمز عبور با PBKDF2 + Salt تصادفی.
    این جایگزین sha256(password) خامه که در برابر rainbow table و brute-force ضعیف بود."""
    return PBKDF2(password.encode("utf-8"), salt, dkLen=32, count=PBKDF2_ITERATIONS)

def load_config():
    global current_lang, logs_enabled, current_theme, kdf_salt, kdf_verifier, saved_keys_raw_blob, saved_keys
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r") as f:
                config = json.load(f)
            if config.get("language") in LANGUAGES: current_lang = config["language"]
            if config.get("theme") in THEMES: current_theme = config["theme"]
            if "logs_enabled" in config: logs_enabled = config["logs_enabled"]
            if "kdf_salt" in config: kdf_salt = base64.b64decode(config["kdf_salt"])
            if "kdf_verifier" in config: kdf_verifier = config["kdf_verifier"]
            if "saved_keys_enc" in config:
                saved_keys_raw_blob = config["saved_keys_enc"]
            elif "saved_keys" in config:
                # مهاجرت از فرمت خیلی قدیمی (base64 ساده، بدون رمزگذاری واقعی).
                # این کلیدها موقتاً در حافظه باز می‌مانند تا کاربر یک رمز اصلی تعیین کند و امن ذخیره شوند.
                try:
                    old = config["saved_keys"]
                    saved_keys.update({k: base64.b64decode(v.encode()).decode('utf-8') for k, v in old.items()})
                except Exception:
                    pass
        except Exception:
            pass

def save_config_file():
    try:
        data = {"language": current_lang, "theme": current_theme, "logs_enabled": logs_enabled}
        if kdf_salt is not None: data["kdf_salt"] = base64.b64encode(kdf_salt).decode("utf-8")
        if kdf_verifier is not None: data["kdf_verifier"] = kdf_verifier
        if saved_keys_raw_blob is not None: data["saved_keys_enc"] = saved_keys_raw_blob
        with open(CONFIG_FILE, "w") as f:
            json.dump(data, f)
    except Exception:
        pass

def persist_saved_keys():
    """کلیدهای موجود در حافظه (saved_keys) را با کلید اصلیِ نشست جاری رمزگذاری و ذخیره می‌کند.
    اگر هنوز رمز اصلی باز/تعیین نشده باشد، چیزی نوشته نمی‌شود (کلیدها فقط در RAM می‌مانند)."""
    global saved_keys_raw_blob
    if master_key is None:
        return
    nonce = get_random_bytes(16)
    cipher = AES.new(master_key, AES.MODE_GCM, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(json.dumps(saved_keys).encode("utf-8"))
    saved_keys_raw_blob = base64.b64encode(nonce + tag + ct).decode("utf-8")
    save_config_file()

def unlock_key_manager() -> bool:
    """رمز اصلی را از کاربر می‌گیرد؛ اگر برای اولین‌بار است، یک رمز جدید تعیین می‌کند.
    کلید نهایی فقط در حافظه نگه داشته می‌شود و هرگز روی دیسک ذخیره نمی‌شود."""
    global master_key, kdf_salt, kdf_verifier, saved_keys
    if kdf_salt is None:
        pw1 = simpledialog.askstring(
            "رمز اصلی جدید" if current_lang == "fa" else "New Master Password",
            "یک رمز اصلی برای محافظت از Key Manager تعیین کنید (حداقل ۴ کاراکتر):" if current_lang == "fa"
            else "Set a master password to protect the Key Manager (min 4 chars):",
            show="*", parent=root)
        if not pw1 or len(pw1) < 4:
            return False
        pw2 = simpledialog.askstring(
            "تکرار رمز" if current_lang == "fa" else "Confirm Password",
            "رمز اصلی را دوباره وارد کنید:" if current_lang == "fa" else "Re-enter the master password:",
            show="*", parent=root)
        if pw1 != pw2:
            messagebox.showerror("ERROR", "رمزهای وارد شده مطابقت ندارند." if current_lang == "fa" else "Passwords do not match.")
            return False
        kdf_salt = get_random_bytes(SALT_SIZE)
        master_key = derive_key(pw1, kdf_salt)
        kdf_verifier = hashlib.sha256(master_key).hexdigest()
        persist_saved_keys()  # کلیدهای مهاجرت‌شده از فرمت قدیمی (اگر بودند) الان امن ذخیره می‌شوند
        save_config_file()
        add_log("Master password created for Key Manager.")
        return True
    else:
        pw = simpledialog.askstring(
            "رمز اصلی" if current_lang == "fa" else "Master Password",
            "رمز اصلی Key Manager را وارد کنید:" if current_lang == "fa" else "Enter the Key Manager master password:",
            show="*", parent=root)
        if pw is None:
            return False
        candidate_key = derive_key(pw, kdf_salt)
        if hashlib.sha256(candidate_key).hexdigest() != kdf_verifier:
            messagebox.showerror("ERROR", "رمز اصلی اشتباه است." if current_lang == "fa" else "Incorrect master password.")
            return False
        master_key = candidate_key
        saved_keys.clear()
        if saved_keys_raw_blob:
            try:
                blob = base64.b64decode(saved_keys_raw_blob.encode())
                nonce, tag, ct = blob[:16], blob[16:32], blob[32:]
                cipher = AES.new(master_key, AES.MODE_GCM, nonce=nonce)
                saved_keys.update(json.loads(cipher.decrypt_and_verify(ct, tag).decode("utf-8")))
            except Exception:
                messagebox.showerror("ERROR", "رمز اصلی اشتباه است یا داده‌ها خراب شده‌اند." if current_lang == "fa" else "Wrong password or corrupted data.")
                master_key = None
                return False
        add_log("Key Manager unlocked.")
        return True

def lock_key_manager():
    """کلید اصلی و کلیدهای رمزگشایی‌شده را از حافظه پاک می‌کند (هنگام بستن پنجره Key Manager)."""
    global master_key
    saved_keys.clear()
    add_log("Key Manager locked.")

def apply_theme(theme_name):
    global current_theme
    if theme_name not in THEMES: return
    current_theme = theme_name
    save_config_file()
    c = THEMES[theme_name]
    
    root.configure(bg=c["bg"])
    top_bar.configure(bg=c["bg"])
    protocol_label.configure(bg=c["bg"], fg=c["accent"])
    
    menu_btn.configure(text="☰", bg=c["input"], fg=c["accent"], activebackground=c["input"], activeforeground=c["accent"])
    
    global_key_frame.configure(bg=c["card"])
    key_title_frame.configure(bg=c["card"])
    lbl_key.configure(bg=c["card"], fg=c["text"])
    strength_label.configure(bg=c["card"])
    key_entry.configure(bg=c["input"], fg=c["accent"], insertbackground=c["accent"])
    
    key_opt_frame.configure(bg=c["card"])
    show_key_btn.configure(bg=c["card"], fg=c["text"], selectcolor=c["input"], activebackground=c["card"], activeforeground=c["text"])
    btn_copy_key.configure(bg=c["btn_secondary"], fg="white")
    btn_rand_key.configure(bg=c["btn_secondary"], fg="white")
    btn_key_manager.configure(bg=c["btn_secondary"], fg="white")
    
    tab_text_frame.configure(bg=c["bg"])
    tab_file_frame.configure(bg=c["bg"])
    lbl_input.configure(bg=c["bg"], fg=c["text"])
    text_entry.configure(bg=c["input"], fg=c["accent"], insertbackground=c["accent"])
    btn_paste.configure(bg=c["btn_secondary"], fg="white")
    btn_frame.configure(bg=c["bg"])
    encrypt_btn.configure(bg=c["btn_primary"], fg="white")
    decrypt_btn.configure(bg=c["accent"], fg=c["bg"] if theme_name != "light" else "white")
    clear_btn.configure(bg=c["btn_secondary"], fg="white")
    lbl_output.configure(bg=c["bg"], fg=c["text"])
    result_entry.configure(bg=c["input"], fg=c["text"], insertbackground=c["text"])
    btn_copy_output.configure(bg=c["accent"], fg=c["bg"] if theme_name != "light" else "white")
    lbl_file.configure(bg=c["bg"], fg=c["text"])
    drop_zone_box.configure(bg=c["card"], fg=c["text"])
    btn_select_file.configure(bg=c["input"], fg=c["accent"])
    lbl_file_status.configure(bg=c["card"])
    file_btn_frame.configure(bg=c["bg"])
    btn_enc_file.configure(bg=c["btn_primary"], fg="white")
    btn_dec_file.configure(bg=c["accent"], fg=c["bg"] if theme_name != "light" else "white")
    log_title_frame.configure(bg=c["bg"])
    lbl_log.configure(bg=c["bg"], fg=c["text"])
    btn_clear_log.configure(bg=c["btn_secondary"], fg="white")
    log_box.configure(bg=c["input"], fg=c["muted"])
    status_label.configure(bg=c["bg"], fg=c["accent"])
    
    style.configure("TNotebook", background=c["bg"])
    style.configure("TNotebook.Tab", background=c["card"], foreground=c["text"])
    style.map("TNotebook.Tab", background=[("selected", c["btn_secondary"])], foreground=[("selected", "#ffffff")])
    style.configure("Horizontal.TProgressbar", troughcolor=c["input"], background=c["accent"], bordercolor=c["bg"])
    update_file_label()
    check_key_strength()

def add_log(message):
    if not logs_enabled: return
    now = datetime.now().strftime("%H:%M:%S")
    log_box.config(state="normal")
    log_box.insert(tk.END, f"[{now}] {message}\n")
    log_box.see(tk.END)
    log_box.config(state="disabled")

def toggle_logs():
    global logs_enabled
    logs_enabled = not logs_enabled
    save_config_file()
    update_log_button_ui()

def clear_logs_action():
    q = "آیا از پاک کردن کامل تاریخچه مطمئن هستید؟ این عمل قابل بازگشت نیست." if current_lang == "fa" \
        else "Are you sure you want to clear all logs? This cannot be undone."
    if not messagebox.askyesno("CONFIRM", q):
        return
    log_box.config(state="normal")
    log_box.delete("1.0", tk.END)
    log_box.config(state="disabled")
    status_label.config(text="تاریخچه عملیات با موفقیت پاک شد" if current_lang == "fa" else "Logs cleared successfully", fg="green")

def update_log_button_ui():
    if logs_enabled: btn_toggle_log.config(text=LANGUAGES[current_lang]["log_active"], bg="#2ed573", fg="white")
    else: btn_toggle_log.config(text=LANGUAGES[current_lang]["log_inactive"], bg="#ff4757", fg="white")

def change_language(lang):
    global current_lang
    current_lang = lang
    save_config_file()
    root.title(LANGUAGES[lang]["title"])
    protocol_label.config(text=LANGUAGES[lang]["protocol"])
    notebook.tab(tab_text_frame, text=LANGUAGES[lang]["tab_text"])
    notebook.tab(tab_file_frame, text=LANGUAGES[lang]["tab_file"])
    lbl_input.config(text=LANGUAGES[lang]["input_label"])
    btn_paste.config(text=LANGUAGES[lang]["paste_btn"])
    lbl_key.config(text=LANGUAGES[lang]["key_label"])
    show_key_btn.config(text=LANGUAGES[lang]["show_key"])
    btn_copy_key.config(text=LANGUAGES[lang]["copy_key"])
    btn_rand_key.config(text=LANGUAGES[lang]["rand_key"])
    btn_key_manager.config(text=LANGUAGES[lang]["key_manager"])
    encrypt_btn.config(text=LANGUAGES[lang]["encrypt"])
    decrypt_btn.config(text=LANGUAGES[lang]["decrypt"])
    clear_btn.config(text=LANGUAGES[lang]["clear"])
    lbl_output.config(text=LANGUAGES[lang]["output_label"])
    btn_copy_output.config(text=LANGUAGES[lang]["copy_output"])
    lbl_file.config(text=LANGUAGES[lang]["file_section"])
    btn_select_file.config(text=LANGUAGES[lang]["select_file_btn"])
    btn_enc_file.config(text=LANGUAGES[lang]["enc_file_btn"])
    btn_dec_file.config(text=LANGUAGES[lang]["dec_file_btn"])
    lbl_log.config(text=LANGUAGES[lang]["log_section"])
    btn_clear_log.config(text=LANGUAGES[lang]["log_clear_btn"])
    update_log_button_ui()
    status_label.config(text=LANGUAGES[lang]["status_online"])
    apply_theme(current_theme)

def show_menu(): menu.post(menu_btn.winfo_rootx(), menu_btn.winfo_rooty() + menu_btn.winfo_height())

def check_for_updates():
    status_label.config(text="در حال بررسی آپدیت..." if current_lang == "fa" else "Checking update...", fg="#ffa500")
    add_log("Checking update server...")
    threading.Thread(target=thread_update_logic, daemon=True).start()

def thread_update_logic():
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
        req = urllib.request.Request(VERSION_URL, headers=headers)
        # از SSL context پیش‌فرض با اعتبارسنجی کامل گواهی استفاده می‌شود (قبلاً غیرفعال بود -> خطر MITM)
        with urllib.request.urlopen(req, timeout=10) as response:
            latest_version = response.read().decode('utf-8').strip()
        if latest_version > CURRENT_VERSION:
            root.after(0, lambda: ask_for_download(latest_version))
        else:
            root.after(0, lambda: [messagebox.showinfo("UPDATE", "برنامه شما به‌روز است!"), add_log("System is up to date.")])
            root.after(0, lambda: status_label.config(text=LANGUAGES[current_lang]["status_online"]))
    except Exception as e:
        error_msg = str(e)
        root.after(0, lambda: [messagebox.showerror("ERROR", f"خطا در اتصال به سرور:\n{error_msg}"), add_log("Update check failed.")])

def ask_for_download(new_version):
    msg = f"نسخه جدید {new_version} در دسترس است. آیا مایلید خودکار دانلود و نصب شود؟"
    if messagebox.askyesno("NEW UPDATE AVAILABLE", msg):
        status_label.config(text="در حال دریافت فایل آپدیت...", fg="#ffa500")
        add_log(f"Downloading v{new_version} package...")
        threading.Thread(target=lambda: thread_download_overhauled(new_version), daemon=True).start()

def fetch_expected_hash(filename):
    """هش SHA-256 رسمی یک فایل را از checksums.txt در ریپازیتوری می‌خواند.
    هر خط این فایل باید به‌فرمت «نام_فایل هش» باشد، مثلاً:
    Anigma_Modern.py 3f9c1a...
    اگر فایل هنوز منتشر نشده یا در دسترس نباشد، None برمی‌گرداند (و آپدیت بدون تایید خودکار ادامه می‌یابد)."""
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

def thread_download_overhauled(new_version):
    try:
        # از SSL context پیش‌فرض با اعتبارسنجی کامل گواهی استفاده می‌شود (قبلاً غیرفعال بود -> خطر MITM)
        current_exe_path = os.path.abspath(sys.argv[0])
        working_dir = os.path.dirname(current_exe_path)
        current_exe_name = os.path.basename(current_exe_path)
        
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'application/octet-stream'
        }
        
        if current_exe_path.endswith(".py"):
            source_url = "https://raw.githubusercontent.com/amirjkkjhk-ux/Anigma-Modern/main/Anigma_Modern.py"
            req = urllib.request.Request(source_url, headers=headers)
            with urllib.request.urlopen(req, timeout=30) as response:
                new_code = response.read()
            if len(new_code) < 1000:
                raise Exception("فایل سورس دریافت شده نامعتبر یا بسیار کوتاه است.")
            new_hash = hashlib.sha256(new_code).hexdigest()
            add_log(f"Downloaded source SHA-256: {new_hash}")

            expected_hash = fetch_expected_hash("Anigma_Modern.py")
            if expected_hash:
                if expected_hash != new_hash:
                    raise Exception(
                        "عدم تطابق هش! فایل دانلودشده ممکن است دستکاری شده باشد و نصب متوقف شد.\n"
                        f"هش مورد انتظار: {expected_hash}\nهش دریافتی: {new_hash}"
                    )
                add_log("Checksum verified against checksums.txt — OK.")
            else:
                add_log("Warning: checksums.txt not found — installing without automatic checksum verification.")

            # پشتیبان‌گیری از نسخه فعلی قبل از جایگزینی، برای امکان بازگشت در صورت مشکل
            backup_path = current_exe_path + ".bak"
            try:
                with open(current_exe_path, "rb") as src, open(backup_path, "wb") as dst:
                    dst.write(src.read())
            except Exception:
                pass
            with open(current_exe_path, "wb") as f:
                f.write(new_code)
            root.after(0, lambda: messagebox.showinfo(
                "SUCCESS",
                "سورس پایتون با موفقیت به نسخه جدید ارتقا یافت!\n"
                f"SHA-256 فایل جدید:\n{new_hash}\n\n"
                "توصیه می‌شود این هش را با هش منتشرشده رسمی مقایسه کنید.\n"
                f"نسخه قبلی در «{os.path.basename(backup_path)}» پشتیبان‌گیری شد."
            ))
            return

        target_release_url = f"https://github.com/amirjkkjhk-ux/Anigma-Modern/releases/download/v{new_version}/Anigma_Modern.exe"
        req = urllib.request.Request(target_release_url, headers=headers)
        
        temp_new_exe = os.path.join(working_dir, "_patch_new_.exe")
        with urllib.request.urlopen(req, timeout=60) as response:
            downloaded_data = response.read()
            
        if len(downloaded_data) < 20000: 
            raise Exception("فایل باینری روی سرور یافت نشد یا ناقص است.\nلطفاً مطمئن شوید فایل Anigma_Modern.exe را در بخش Assets ریلیز قرار داده‌اید.")
            
        with open(temp_new_exe, "wb") as f:
            f.write(downloaded_data)

        new_hash = hashlib.sha256(downloaded_data).hexdigest()
        add_log(f"Downloaded update SHA-256: {new_hash}")

        expected_hash = fetch_expected_hash("Anigma_Modern.exe")
        if expected_hash:
            if expected_hash != new_hash:
                try: os.remove(temp_new_exe)
                except Exception: pass
                raise Exception(
                    "عدم تطابق هش! فایل دانلودشده ممکن است دستکاری شده باشد و نصب متوقف شد.\n"
                    f"هش مورد انتظار: {expected_hash}\nهش دریافتی: {new_hash}"
                )
            add_log("Checksum verified against checksums.txt — OK.")
        else:
            add_log("Warning: checksums.txt not found — installing without automatic checksum verification.")

        bat_path = os.path.join(working_dir, "safe_installer.bat")
        backup_name = current_exe_name + ".bak"
        with open(bat_path, "w") as b:
            b.write('@echo off\n')
            b.write('title Anigma Modern Core Recovery\n')
            b.write(f'taskkill /f /im "{current_exe_name}" >nul 2>&1\n')
            b.write(':loop\n')
            b.write('timeout /t 1 /nobreak > nul\n')
            # به‌جای حذف مستقیم، از فایل فعلی یک نسخه پشتیبان می‌گیریم تا در صورت خرابی آپدیت قابل بازگردانی باشد
            b.write(f'copy /y "{current_exe_path}" "{backup_name}" >nul 2>&1\n')
            b.write(f'del /f /q "{current_exe_path}" >nul 2>&1\n')
            b.write(f'if exist "{current_exe_path}" goto loop\n') 
            b.write(f'move /y "_patch_new_.exe" "{current_exe_path}" >nul 2>&1\n')
            b.write(f'start "" "{current_exe_path}"\n')
            b.write('del "%~f0"\n')
            
        root.after(0, lambda: messagebox.showinfo(
            "DOWNLOAD OK",
            "فایل آپدیت با موفقیت دریافت شد. برنامه ری‌استارت می‌شود.\n\n"
            f"SHA-256:\n{new_hash}\n"
            "توصیه می‌شود این هش را با هش منتشرشده رسمی روی گیت‌هاب مقایسه کنید."
        ))
        
        subprocess.Popen([bat_path], shell=True, cwd=working_dir, creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
        root.after(0, root.quit)
        sys.exit(0)
        
    except Exception as e:
        error_msg = str(e)
        root.after(0, lambda: messagebox.showerror("CRITICAL ERROR", f"خطا در پروسه آپدیت خودکار:\n{error_msg}"))

def open_help():
    help_window = tk.Toplevel(root)
    help_window.title("ABOUT & USER GUIDE")
    help_window.geometry("550x560")
    help_window.configure(bg=THEMES[current_theme]["card"])
    
    title_frame = tk.LabelFrame(help_window, text=" شناسنامه سازنده پروژه ", bg=help_window["bg"], fg=THEMES[current_theme]["accent"], font=("Segoe UI", 10, "bold"))
    title_frame.pack(fill="x", padx=15, pady=10)
    
    tk.Label(title_frame, text="توسعه دهنده و مالک اصلی آنیگما مدرن:", bg=help_window["bg"], fg="white", font=("Segoe UI", 10)).pack(pady=2)
    tk.Label(title_frame, text="امیر مهدی بساوند (Amir Mehdi Basavand)", bg=help_window["bg"], fg=THEMES[current_theme]["btn_primary"], font=("Segoe UI", 12, "bold")).pack(pady=2)
    tk.Label(title_frame, text="ایمیل: amirjkkjhk@gmail.com", bg=help_window["bg"], fg="gray", font=("Consolas", 10)).pack(pady=4)

    guide_frame = tk.LabelFrame(help_window, text=" راهنمای کامل استفاده از برنامه ", bg=help_window["bg"], fg=THEMES[current_theme]["accent"], font=("Segoe UI", 10, "bold"))
    guide_frame.pack(fill="both", expand=True, padx=15, pady=10)
    
    text_area = tk.Text(guide_frame, bg=THEMES[current_theme]["input"], fg="white", wrap="word", font=("Segoe UI", 10), bd=0)
    text_area.pack(fill="both", expand=True, padx=5, pady=5)
    
    guide_text = (
        "بخش اول: تنظیم کلید امنیتی (Secret Key)\n"
        "قبل از انجام هر کاری، باید یک کلید امنیتی در کادر بالا وارد کنید. این کلید برای قفل کردن و باز کردن اطلاعات استفاده می شود. می توانید از دکمه تولید کلید تصادفی برای داشتن یک رمز فوق امنیتی استفاده کنید. همچنین با دکمه مدیریت کلیدها می توانید رمزهای خود را ذخیره و مدیریت کنید.\n\n"
        "بخش دوم: قفل گذاری و رمزگشایی متنی (Text Encryption)\n"
        "1. متن عادی خود را در کادر شماره 1 وارد کنید یا از دکمه جاگذاری برای چسباندن متن کپی شده استفاده کنید.\n"
        "2. کلید امنیتی را وارد کنید.\n"
        "3. دکمه رمزگذاری متنی را بزنید تا متن شما به کدهای نامفهوم تبدیل شود و در کادر شماره 2 نمایش داده شود.\n"
        "4. برای باز کردن متن رمز شده، متن نامفهوم را در کادر شماره 1 قرار داده، کلید مربوطه را وارد کنید و دکمه رمزگشایی متنی را بزنید.\n\n"
        "بخش سوم: قفل گذاری و رمزگشایی فایل (File Encryption)\n"
        "1. به تب قفل گذاری فایل بروید.\n"
        "2. فایل مورد نظر خود را بکشید و داخل کادر مشخص شده رها کنید، یا روی دکمه انتخاب فایل کلیک کرده و آن را از کامپیوتر خود انتخاب کنید.\n"
        "3. کلید امنیتی را در کادر بالا وارد کنید.\n"
        "4. دکمه رمزگذاری فایل را بزنید تا فایل شما با الگوریتم قدرتمند و به صورت فشرده قفل شود. فایل خروجی با پسوند anigma ذخیره می شود.\n"
        "5. برای باز کردن فایل قفل شده، همان فایل anigma را انتخاب کرده، رمز صحیح را وارد کنید و دکمه رمزگشایی فایل را بزنید تا فایل اصلی بازیابی شود."
    )
    text_area.insert("1.0", guide_text)
    text_area.config(state="disabled")

def open_key_manager():
    if not unlock_key_manager():
        return  # رمز اشتباه بود یا کاربر انصراف داد

    def refresh_list():
        listbox.delete(0, tk.END)
        for name in saved_keys: listbox.insert(tk.END, name)
    def add_new_key():
        n, v = name_entry.get().strip(), val_entry.get().strip()
        if n and v:
            saved_keys[n] = v
            persist_saved_keys()
            refresh_list()
            add_log(f"Key saved: '{n}'")
    def delete_key():
        try:
            target = listbox.get(listbox.curselection())
            del saved_keys[target]
            persist_saved_keys()
            refresh_list()
            add_log(f"Key deleted: '{target}'")
        except Exception:
            pass
    def select_key(e):
        try: key_entry.delete(0, tk.END); key_entry.insert(0, saved_keys[listbox.get(listbox.curselection())]); check_key_strength(); add_log("Key loaded from manager."); on_close()
        except Exception: pass
    def on_close():
        lock_key_manager()
        manager_win.destroy()

    manager_win = tk.Toplevel(root)
    manager_win.geometry("360x420")
    manager_win.configure(bg=THEMES[current_theme]["card"])
    manager_win.protocol("WM_DELETE_WINDOW", on_close)
    listbox = tk.Listbox(manager_win, bg=THEMES[current_theme]["input"], fg=THEMES[current_theme]["accent"])
    listbox.pack(fill="both", expand=True, padx=10, pady=5)
    listbox.bind('<Double-1>', select_key)
    refresh_list()
    f = tk.Frame(manager_win, bg=THEMES[current_theme]["card"])
    f.pack(fill="x", padx=10)
    name_entry = tk.Entry(f, width=10); name_entry.pack(side="left", padx=2)
    val_entry = tk.Entry(f, width=15); val_entry.pack(side="left", padx=2)
    tk.Button(f, text="+", command=add_new_key).pack(side="right")
    tk.Button(manager_win, text="Delete", command=delete_key, bg="#ff4757", fg="white").pack(fill="x", pady=5)

def drop_inside_file_zone(event):
    global selected_file_path
    p = event.data
    if p.startswith('{'): p = p[1:-1]
    if os.path.exists(p): selected_file_path = p; update_file_label(); add_log(f"File loaded via Drag&Drop: {os.path.basename(p)}")

def select_file():
    global selected_file_path
    p = filedialog.askopenfilename()
    if p: selected_file_path = p; update_file_label(); add_log(f"File selected: {os.path.basename(p)}")

def update_file_label():
    c = THEMES[current_theme]
    lbl_file_status.config(text=os.path.basename(selected_file_path) if selected_file_path else "فایلی انتخاب نشده", fg=c["accent"] if selected_file_path else c["muted"])

def set_buttons_state(state):
    btn_enc_file.config(state=state)
    btn_dec_file.config(state=state)
    btn_select_file.config(state=state)

def start_file_thread(action):
    if not selected_file_path or not key_entry.get(): 
        messagebox.showwarning("WARNING", LANGUAGES[current_lang]["warning_no_file"])
        return
    status_label.config(text=LANGUAGES[current_lang]["processing"], fg="#ffa500")
    set_buttons_state("disabled")
    progress_bar["value"] = 0
    if action == "encrypt": threading.Thread(target=process_encrypt_file, daemon=True).start()
    else: threading.Thread(target=process_decrypt_file, daemon=True).start()

def process_encrypt_file():
    key = None
    try:
        salt = get_random_bytes(SALT_SIZE)
        key = derive_key(key_entry.get(), salt)
        cipher = AES.new(key, AES.MODE_GCM)
        compressor = zlib.compressobj()

        total_size = os.path.getsize(selected_file_path)
        out = selected_file_path + ".anigma"
        chunk_size = 64 * 1024
        read_bytes = 0

        # فرمت فایل خروجی: salt(16) + nonce(16) + ciphertext(...) + tag(16)
        # پردازش به‌صورت استریمی (خواندن/فشرده‌سازی/رمزگذاری/نوشتن چانک‌به‌چانک)
        # انجام می‌شود تا کل فایل مبدا و خروجی فشرده هم‌زمان در RAM نگه داشته نشوند.
        with open(out, "wb") as fout:
            fout.write(salt + cipher.nonce)
            with open(selected_file_path, "rb") as fin:
                while True:
                    chunk = fin.read(chunk_size)
                    if not chunk:
                        break
                    read_bytes += len(chunk)
                    compressed_chunk = compressor.compress(chunk)
                    if compressed_chunk:
                        fout.write(cipher.encrypt(compressed_chunk))
                    progress = int((read_bytes / total_size) * 100) if total_size else 100
                    root.after(0, lambda p=progress: progress_bar.configure(value=p))
            final_chunk = compressor.flush()
            if final_chunk:
                fout.write(cipher.encrypt(final_chunk))
            fout.write(cipher.digest())

        root.after(0, lambda: file_success_ui(out, "enc"))
    except Exception as e:
        root.after(0, lambda: [messagebox.showerror("ERROR", str(e)), status_label.config(text=LANGUAGES[current_lang]["status_online"])])
    finally:
        key = None  # پاکسازی کلید از این متغیر بلافاصله بعد از استفاده
        root.after(0, lambda: set_buttons_state("normal"))

def process_decrypt_file():
    key = None
    tmp_out = None
    try:
        total_file_size = os.path.getsize(selected_file_path)
        ciphertext_len = total_file_size - SALT_SIZE - 16 - 16  # منهای salt، nonce و tag
        if ciphertext_len < 0:
            raise Exception("Corrupted or truncated file.")

        out = selected_file_path[:-7] if selected_file_path.endswith(".anigma") else selected_file_path + ".dec"
        tmp_out = out + ".tmp"
        chunk_size = 64 * 1024

        with open(selected_file_path, "rb") as f:
            salt = f.read(SALT_SIZE)
            nonce = f.read(16)
            key = derive_key(key_entry.get(), salt)
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            decompressor = zlib.decompressobj()

            remaining = ciphertext_len
            read_total = 0
            # نکته امنیتی: خروجی ابتدا در یک فایل موقت (.tmp) نوشته می‌شود.
            # فقط بعد از تایید موفق GCM tag، فایل موقت به نام نهایی تغییر نام می‌یابد؛
            # در غیر این صورت (رمز اشتباه/داده دستکاری‌شده) فایل موقت حذف و چیزی به کاربر تحویل داده نمی‌شود.
            with open(tmp_out, "wb") as fout:
                while remaining > 0:
                    chunk = f.read(min(chunk_size, remaining))
                    if not chunk:
                        break
                    remaining -= len(chunk)
                    read_total += len(chunk)
                    plain_chunk = decompressor.decompress(cipher.decrypt(chunk))
                    if plain_chunk:
                        fout.write(plain_chunk)
                    progress = int((read_total / ciphertext_len) * 100) if ciphertext_len else 100
                    root.after(0, lambda p=progress: progress_bar.configure(value=p))
                fout.write(decompressor.flush())

            tag = f.read(16)
            cipher.verify(tag)  # اگر رمز غلط باشد یا فایل دستکاری شده باشد، اینجا استثنا پرتاب می‌شود

        os.replace(tmp_out, out)  # تایید موفق -> جایگزینی نهایی
        tmp_out = None
        root.after(0, lambda: file_success_ui(out, "dec"))
    except Exception:
        root.after(0, lambda: [messagebox.showerror("ERROR", LANGUAGES[current_lang]["error_decrypt"]), status_label.config(text=LANGUAGES[current_lang]["status_online"])])
    finally:
        if tmp_out and os.path.exists(tmp_out):
            try: os.remove(tmp_out)
            except Exception: pass
        key = None  # پاکسازی کلید از این متغیر بلافاصله بعد از استفاده
        root.after(0, lambda: set_buttons_state("normal"))

def file_success_ui(p, mode): 
    messagebox.showinfo("OK", f"عملیات موفقیت‌آمیز:\n{os.path.basename(p)}")
    status_label.config(text=LANGUAGES[current_lang]["status_file_enc"] if mode == "enc" else LANGUAGES[current_lang]["status_file_dec"], fg="green")
    add_log(f"File {'encrypted' if mode == 'enc' else 'decrypted'} -> {os.path.basename(p)}")

def copy_output():
    t = result_entry.get("1.0", tk.END).strip()
    if t: 
        root.clipboard_clear(); root.clipboard_append(t)
        status_label.config(text=LANGUAGES[current_lang]["status_copied"], fg="green")
        add_log("Ciphertext copied to clipboard.")

def copy_key():
    k = key_entry.get().strip()
    if k: 
        root.clipboard_clear(); root.clipboard_append(k)
        status_label.config(text=LANGUAGES[current_lang]["status_key_copied"], fg="green")
        add_log("Secret key copied.")

def paste_input():
    try: 
        text_entry.delete("1.0", tk.END); text_entry.insert("1.0", root.clipboard_get())
        status_label.config(text=LANGUAGES[current_lang]["status_pasted"], fg="green")
    except: status_label.config(text=LANGUAGES[current_lang]["status_paste_failed"], fg="red")

def toggle_password_visibility(): key_entry.config(show="" if show_key_var.get() else "*")

def generate_random_key():
    # ساخت کلید امنیتی با استاندارد بالا همراه با کاراکترهای خاص
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
    secure_key = "".join(secrets.choice(alphabet) for _ in range(16))
    key_entry.delete(0, tk.END)
    key_entry.insert(0, secure_key)
    check_key_strength()
    add_log("New high-secure random key generated.")

def check_key_strength(e=None):
    k = key_entry.get()
    if not k: strength_label.config(text=LANGUAGES[current_lang]["key_empty"], fg="gray")
    elif len(k) < 6: strength_label.config(text=LANGUAGES[current_lang]["key_weak"], fg="red")
    elif len(k) < 12: strength_label.config(text=LANGUAGES[current_lang]["key_good"], fg="orange")
    else: strength_label.config(text=LANGUAGES[current_lang]["key_military"], fg="green")

def encode_message():
    txt, k = text_entry.get("1.0", tk.END).strip(), key_entry.get().strip()
    if not txt or not k: 
        messagebox.showwarning("WARNING", LANGUAGES[current_lang]["warning_empty"])
        return
    try:
        salt = get_random_bytes(SALT_SIZE)
        key = derive_key(k, salt)
        cipher = AES.new(key, AES.MODE_GCM)
        ctx, tag = cipher.encrypt_and_digest(txt.encode('utf-8'))
        # فرمت خروجی: salt(16) + nonce(16) + tag(16) + ciphertext
        result_entry.delete("1.0", tk.END); result_entry.insert("1.0", base64.urlsafe_b64encode(salt + cipher.nonce + tag + ctx).decode('utf-8'))
        status_label.config(text=LANGUAGES[current_lang]["status_encrypted"], fg="green")
        add_log("Text encryption successful.")
    except Exception as e: messagebox.showerror("ERROR", str(e))
    finally: key = None

def decode_message():
    ctx, k = text_entry.get("1.0", tk.END).strip(), key_entry.get().strip()
    if not ctx or not k: 
        messagebox.showwarning("WARNING", LANGUAGES[current_lang]["warning_empty"])
        return
    try:
        r = base64.urlsafe_b64decode(ctx.encode('utf-8'))
        salt, nonce, tag, encrypted = r[:16], r[16:32], r[32:48], r[48:]
        key = derive_key(k, salt)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        result_entry.delete("1.0", tk.END); result_entry.insert("1.0", cipher.decrypt_and_verify(encrypted, tag).decode('utf-8'))
        status_label.config(text=LANGUAGES[current_lang]["status_decrypted"], fg="green")
        add_log("Text decryption successful.")
    except Exception:
        messagebox.showerror("ERROR", LANGUAGES[current_lang]["error_decrypt"])
    finally:
        key = None

def clear_all(): 
    text_entry.delete("1.0", tk.END); key_entry.delete(0, tk.END); result_entry.delete("1.0", tk.END)
    status_label.config(text=LANGUAGES[current_lang]["status_cleared"], fg="gray")

load_config()
root = TkinterDnD.Tk()
root.geometry("540x670") 
root.resizable(False, False)
style = ttk.Style()
style.theme_use('default')

top_bar = tk.Frame(root)
top_bar.pack(fill="x", padx=10, pady=5)

menu_btn = tk.Button(top_bar, text="☰", font=("Segoe UI", 11, "bold"), bd=0)
menu_btn.pack(side="left")

protocol_label = tk.Label(top_bar, font=("Segoe UI", 9, "bold"))
protocol_label.pack(side="left", expand=True)

global_key_frame = tk.Frame(root, bd=1, relief="solid")
global_key_frame.pack(fill="x", padx=15, pady=5)
key_title_frame = tk.Frame(global_key_frame)
key_title_frame.pack(fill="x", padx=10, pady=2)
lbl_key = tk.Label(key_title_frame)
lbl_key.pack(side="left")
strength_label = tk.Label(key_title_frame)
strength_label.pack(side="right")
key_entry = tk.Entry(global_key_frame, font=("Arial", 11, "bold"), show="*", bd=1, relief="solid")
key_entry.pack(fill="x", padx=10, pady=2)
key_entry.bind("<KeyRelease>", check_key_strength)
key_opt_frame = tk.Frame(global_key_frame)
key_opt_frame.pack(fill="x", padx=10, pady=4)
show_key_var = tk.BooleanVar()
show_key_btn = tk.Checkbutton(key_opt_frame, variable=show_key_var, command=toggle_password_visibility)
show_key_btn.pack(side="left")
btn_copy_key = tk.Button(key_opt_frame, command=copy_key)
btn_copy_key.pack(side="right", padx=2)
btn_rand_key = tk.Button(key_opt_frame, command=generate_random_key)
btn_rand_key.pack(side="right", padx=2)
btn_key_manager = tk.Button(key_opt_frame, command=open_key_manager)
btn_key_manager.pack(side="right", padx=2)

notebook = ttk.Notebook(root)
notebook.pack(fill="both", expand=True, padx=15, pady=5)
tab_text_frame = tk.Frame(notebook)
tab_file_frame = tk.Frame(notebook)
notebook.add(tab_text_frame)
notebook.add(tab_file_frame)

lbl_input = tk.Label(tab_text_frame)
lbl_input.pack(anchor="w", padx=10, pady=2)
text_entry = tk.Text(tab_text_frame, height=3, width=58, bd=1, relief="solid")
text_entry.pack()
btn_paste = tk.Button(tab_text_frame, command=paste_input)
btn_paste.pack(fill="x", padx=10, pady=4)
btn_frame = tk.Frame(tab_text_frame)
btn_frame.pack(pady=4)
encrypt_btn = tk.Button(btn_frame, command=encode_message)
encrypt_btn.pack(side="left", padx=5)
decrypt_btn = tk.Button(btn_frame, command=decode_message)
decrypt_btn.pack(side="left", padx=5)
clear_btn = tk.Button(btn_frame, command=clear_all)
clear_btn.pack(side="left", padx=5)
lbl_output = tk.Label(tab_text_frame)
lbl_output.pack(anchor="w", padx=10, pady=2)
result_entry = tk.Text(tab_text_frame, height=3, width=58, bd=1, relief="solid")
result_entry.pack()
btn_copy_output = tk.Button(tab_text_frame, command=copy_output)
btn_copy_output.pack(fill="x", padx=10, pady=4)

lbl_file = tk.Label(tab_file_frame)
lbl_file.pack(anchor="w", padx=10, pady=10)
drop_zone_box = tk.LabelFrame(tab_file_frame, bd=1, relief="solid")
drop_zone_box.pack(fill="x", padx=10, pady=5, ipady=15)
drop_zone_box.drop_target_register(DND_FILES)
drop_zone_box.dnd_bind('<<Drop>>', drop_inside_file_zone)
btn_select_file = tk.Button(drop_zone_box, command=select_file)
btn_select_file.pack(pady=5)
lbl_file_status = tk.Label(drop_zone_box)
lbl_file_status.pack(pady=2)
file_btn_frame = tk.Frame(tab_file_frame)
file_btn_frame.pack(pady=10)
btn_enc_file = tk.Button(file_btn_frame, command=lambda: start_file_thread("encrypt"))
btn_enc_file.pack(side="left", padx=10)
btn_dec_file = tk.Button(file_btn_frame, command=lambda: start_file_thread("decrypt"))
btn_dec_file.pack(side="left", padx=10)
progress_bar = ttk.Progressbar(tab_file_frame, orient="horizontal", length=430, mode="determinate")
progress_bar.pack(pady=5)

log_title_frame = tk.Frame(root)
log_title_frame.pack(fill="x", padx=35, pady=2)
lbl_log = tk.Label(log_title_frame)
lbl_log.pack(side="right")
btn_toggle_log = tk.Button(log_title_frame, command=toggle_logs)
btn_toggle_log.pack(side="left", padx=2)
btn_clear_log = tk.Button(log_title_frame, command=clear_logs_action)
btn_clear_log.pack(side="left", padx=2)

log_container = tk.Frame(root)
log_container.pack(fill="x", padx=15, pady=2)

scrollbar_y = tk.Scrollbar(log_container, orient="vertical")
scrollbar_y.pack(side="right", fill="y")

log_box = tk.Text(log_container, height=4, width=55, bd=1, relief="solid", state="disabled", font=("Consolas", 9), yscrollcommand=scrollbar_y.set)
log_box.pack(side="left", fill="both", expand=True)
scrollbar_y.config(command=log_box.yview)

status_label = tk.Label(root)
status_label.pack(side="bottom", pady=5)

menu = tk.Menu(root, tearoff=0)
menu.add_command(label=f"Version: {CURRENT_VERSION}", state="disabled")
menu.add_command(label=LANGUAGES[current_lang]["menu_help"], command=open_help)
menu.add_command(label=LANGUAGES[current_lang]["menu_update"], command=check_for_updates)

# ==================== لایه افزوده شده: منوی سوییچ آنلاین زبان ====================
lang_menu = tk.Menu(menu, tearoff=0)
lang_menu.add_command(label="فارسی", command=lambda: change_language("fa"))
lang_menu.add_command(label="English", command=lambda: change_language("en"))
menu.add_cascade(label="Language / زبان", menu=lang_menu)
# ==============================================================================

theme_menu = tk.Menu(menu, tearoff=0)
theme_menu.add_command(label="Night", command=lambda: apply_theme("night"))
theme_menu.add_command(label="Hacker", command=lambda: apply_theme("hacker"))
theme_menu.add_command(label="Light", command=lambda: apply_theme("light"))
menu.add_cascade(label="Theme", menu=theme_menu)
menu_btn.config(command=show_menu)

change_language(current_lang)
add_log("Anigma Core Engine initialized successfully.")
root.mainloop()
