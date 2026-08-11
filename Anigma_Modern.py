# DEVELOPER: Amir Mehdi Basavand (امیر مهدی بساوند)
# EMAIL: amirjkkjhk@gmail.com
# TELEGRAM ID: @Amirshoq
# ====================================================================================
# PROJECT: ANIGMA MODERN PRO | DARK NEON EDITION v17.5
# ====================================================================================

import tkinter as tk
from tkinter import messagebox, ttk, filedialog, simpledialog
import base64
import hashlib
import secrets
import string
import os
import sys
import zlib
import threading
import json
import subprocess
from datetime import datetime
import urllib.request 
import urllib.error

try:
    from tkinterdnd2 import TkinterDnD, DND_FILES 
    HAS_DND = True
except ImportError:
    HAS_DND = False

from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes

CONFIG_FILE = "config.json"
CURRENT_VERSION = "17.5"
PBKDF2_ITERATIONS = 200_000
SALT_SIZE = 16

# آدرس‌های اصلاح‌شده (حذف پسوند اضافی .txt.txt)
VERSION_URL = "https://raw.githubusercontent.com/amirjkkjhk-ux/Anigma-Modern/main/version.txt"
CHECKSUMS_URL = "https://raw.githubusercontent.com/amirjkkjhk-ux/Anigma-Modern/main/checksums.txt"

LANGUAGES = {
    "fa": {
        "title": f"ANIGMA MODERN PRO v{CURRENT_VERSION}",
        "protocol": "پروتکل: AES-256 + Zlib Engine",
        "settings_menu": "☰ تنظیمات",
        "tab_text": "قفل‌گذاری متنی",
        "tab_file": "قفل‌گذاری فایل",
        "input_label": "۱. متن اصلی یا رمزگذاری شده را وارد کنید:",
        "paste_btn": "جاگذاری متن کپی شده (PASTE)",
        "key_label": "کلید امنیتی اختصاصی (SECRET KEY):",
        "key_empty": "خالی",
        "key_weak": "ضعیف",
        "key_good": "متوسط",
        "key_military": "فوق امنیتی (نظامی)",
        "show_key": "نمایش رمز",
        "copy_key": "کپی رمز",
        "rand_key": "تولید کلید تصادفی",
        "key_manager": "مدیریت کلیدها",
        "encrypt": "رمزگذاری متنی",
        "decrypt": "رمزگشایی متنی",
        "clear": "پاک‌سازی فرم",
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
        "status_file_enc": "وضعیت: فایل با موفقیت رمزگذاری شد!",
        "status_file_dec": "وضعیت: فایل با موفقیت رمزگشایی شد!",
        "warning_empty": "لطفاً متن ورودی و کلید امنیتی را وارد کنید!",
        "warning_no_file": "لطفاً ابتدا یک فایل انتخاب کرده و رمز را وارد کنید!",
        "error_decrypt": "رمز عبور اشتباه است یا پیام دستکاری شده!",
        "menu_help": "راهنمای کامل و شناسنامه سازنده",
        "menu_update": "بررسی آپدیت آنلاین",
        "menu_changelog": "تغییرات آخرین آپدیت",
        "processing": "وضعیت: در حال پردازش فایل... لطفاً صبر کنید",
        "file_not_selected": "فایلی انتخاب نشده است",
        "help_title": "راهنما و درباره سازنده",
        "help_dev_info": "شناسنامه سازنده پروژه",
        "help_app_intro_title": "معرفی کامل برنامه",
        "help_app_intro_text": "برنامه ANIGMA MODERN PRO یک ابزار پیشرفته برای رمزگذاری و امنیت اطلاعات است. این نرم‌افزار از الگوریتم استاندارد رمزنگاری پیشرفته AES با طول کلید ۲۵۶ بیت در حالت GCM استفاده می‌کند.",
        "help_usage_title": "آموزش نحوه استفاده",
        "help_usage_text": "۱. قفل‌گذاری متنی:\n - کلید امنیتی را وارد کرده و متن را رمزگذاری/رمزگشایی کنید.\n\n۲. قفل‌گذاری فایل:\n - فایل را انتخاب یا Drag & Drop کرده و دکمه مربوطه را بزنید.",
        "changelog_title": "تغییرات آخرین آپدیت (v17.5)",
        "changelog_text": "- رفع خطای 404 در بخش بررسی آپدیت آنلاین\n- بازگرداندن متن «تنظیمات» به منوی همبرگری\n- ارتقا و مدرن‌سازی ظاهر برنامه‌"
    },
    "en": {
        "title": f"ANIGMA MODERN PRO v{CURRENT_VERSION}",
        "protocol": "PROTOCOL: AES-256 + Zlib ENGINE",
        "settings_menu": "☰ Settings",
        "tab_text": "Text Vault",
        "tab_file": "File Vault",
        "input_label": "1. Enter Plain text or Cipher text:",
        "paste_btn": "PASTE COPIED TEXT",
        "key_label": "Global SECRET KEY:",
        "key_empty": "EMPTY",
        "key_weak": "WEAK",
        "key_good": "GOOD",
        "key_military": "MILITARY GRADE",
        "show_key": "Show Key",
        "copy_key": "Copy Key",
        "rand_key": "Random Key",
        "key_manager": "Key Manager",
        "encrypt": "ENCRYPT TEXT",
        "decrypt": "DECRYPT TEXT",
        "clear": "CLEAR FORM",
        "output_label": "2. System Output:",
        "copy_output": "COPY OUTPUT TEXT",
        "file_section": "File Vault (Select or Drag & Drop File here):",
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
        "status_paste_failed": "STATUS: PASTE FAILED!",
        "status_encrypted": "STATUS: TEXT ENCRYPTED SUCCESS!",
        "status_decrypted": "STATUS: TEXT DECRYPTED SUCCESS!",
        "status_cleared": "STATUS: TERMINAL CLEARED",
        "status_file_enc": "STATUS: FILE ENCRYPTED SUCCESS!",
        "status_file_dec": "STATUS: FILE DECRYPTED SUCCESS!",
        "warning_empty": "Input text or secret key is empty!",
        "warning_no_file": "Please select a file and enter a secret key first!",
        "error_decrypt": "Wrong key or corrupted data!",
        "menu_help": "User Guide & Developer Info",
        "menu_update": "Check for Updates",
        "menu_changelog": "Latest Update Changelog",
        "processing": "STATUS: Processing file... Please wait",
        "file_not_selected": "No file selected",
        "help_title": "Guide & Developer Info",
        "help_dev_info": "Developer Info",
        "help_app_intro_title": "Full Application Overview",
        "help_app_intro_text": "ANIGMA MODERN PRO is an advanced cryptographic tool designed for data security.",
        "help_usage_title": "How to Use",
        "help_usage_text": "1. Text Vault: Enter key & perform action.\n2. File Vault: Drag & drop file to encrypt/decrypt.",
        "changelog_title": "Latest Update Changelog (v17.5)",
        "changelog_text": "- Fixed HTTP 404 update URL issue\n- Restored settings text alongside hamburger icon\n- UI/UX polish"
    }
}

THEMES = {
    "night": {
        "bg": "#0b0e14",
        "card": "#161b22",
        "card_border": "#30363d",
        "input": "#0d1117",
        "text": "#f0f6fc",
        "accent": "#00f0ff",
        "btn_primary": "#ff0055",
        "btn_secondary": "#0066ff",
        "btn_dark": "#21262d",
        "muted": "#8b949e"
    }
}

FONT_MAIN = ("Segoe UI", 9)
FONT_BOLD = ("Segoe UI", 9, "bold")
FONT_TITLE = ("Segoe UI", 10, "bold")
FONT_CODE = ("Consolas", 9, "bold")

current_lang = "fa"
current_theme = "night"
selected_file_path = ""
logs_enabled = True
saved_keys = {}
saved_keys_raw_blob = None
kdf_salt = None
kdf_verifier = None
master_key = None

def derive_key(password: str, salt: bytes) -> bytes:
    return PBKDF2(password.encode("utf-8"), salt, dkLen=32, count=PBKDF2_ITERATIONS)

def load_config():
    global current_lang, logs_enabled, kdf_salt, kdf_verifier, saved_keys_raw_blob, saved_keys
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                config = json.load(f)
            if config.get("language") in LANGUAGES: current_lang = config["language"]
            if "logs_enabled" in config: logs_enabled = config["logs_enabled"]
            if "kdf_salt" in config: kdf_salt = base64.b64decode(config["kdf_salt"])
            if "kdf_verifier" in config: kdf_verifier = config["kdf_verifier"]
            if "saved_keys_enc" in config:
                saved_keys_raw_blob = config["saved_keys_enc"]
        except Exception:
            pass

def save_config_file():
    try:
        data = {"language": current_lang, "theme": "night", "logs_enabled": logs_enabled}
        if kdf_salt is not None: data["kdf_salt"] = base64.b64encode(kdf_salt).decode("utf-8")
        if kdf_verifier is not None: data["kdf_verifier"] = kdf_verifier
        if saved_keys_raw_blob is not None: data["saved_keys_enc"] = saved_keys_raw_blob
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f)
    except Exception:
        pass

def persist_saved_keys():
    global saved_keys_raw_blob
    if master_key is None: return
    nonce = get_random_bytes(16)
    cipher = AES.new(master_key, AES.MODE_GCM, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(json.dumps(saved_keys).encode("utf-8"))
    saved_keys_raw_blob = base64.b64encode(nonce + tag + ct).decode("utf-8")
    save_config_file()

def unlock_key_manager() -> bool:
    global master_key, kdf_salt, kdf_verifier, saved_keys
    if kdf_salt is None:
        pw1 = simpledialog.askstring("رمز اصلی", "یک رمز اصلی تعیین کنید (حداقل ۴ کاراکتر):", show="*", parent=root)
        if not pw1 or len(pw1) < 4: return False
        pw2 = simpledialog.askstring("تکرار رمز", "رمز اصلی را دوباره وارد کنید:", show="*", parent=root)
        if pw1 != pw2:
            messagebox.showerror("خطا", "رمزهای وارد شده مطابقت ندارند.")
            return False
        kdf_salt = get_random_bytes(SALT_SIZE)
        master_key = derive_key(pw1, kdf_salt)
        kdf_verifier = hashlib.sha256(master_key).hexdigest()
        persist_saved_keys()
        save_config_file()
        add_log("Master password created.")
        return True
    else:
        pw = simpledialog.askstring("رمز اصلی", "رمز اصلی Key Manager را وارد کنید:", show="*", parent=root)
        if pw is None: return False
        candidate_key = derive_key(pw, kdf_salt)
        if hashlib.sha256(candidate_key).hexdigest() != kdf_verifier:
            messagebox.showerror("خطا", "رمز اصلی اشتباه است.")
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
                messagebox.showerror("خطا", "رمز اشتباه یا داده‌ها خراب شده‌اند.")
                master_key = None
                return False
        add_log("Key Manager unlocked.")
        return True

def lock_key_manager():
    global master_key
    saved_keys.clear()
    add_log("Key Manager locked.")

def apply_theme():
    c = THEMES["night"]
    root.configure(bg=c["bg"])
    top_bar.configure(bg=c["bg"])
    protocol_label.configure(bg=c["bg"], fg=c["accent"], font=FONT_BOLD)
    menu_btn.configure(bg=c["card"], fg=c["accent"], activebackground=c["input"], activeforeground=c["accent"], font=FONT_BOLD)
    
    global_key_frame.configure(bg=c["card"], highlightbackground=c["card_border"], highlightthickness=1)
    key_title_frame.configure(bg=c["card"])
    lbl_key.configure(bg=c["card"], fg=c["text"], font=FONT_BOLD)
    strength_label.configure(bg=c["card"], font=FONT_BOLD)
    key_entry.configure(bg=c["input"], fg=c["accent"], insertbackground=c["accent"], font=FONT_CODE)
    
    key_opt_frame.configure(bg=c["card"])
    show_key_btn.configure(bg=c["card"], fg=c["text"], selectcolor=c["input"], activebackground=c["card"], activeforeground=c["text"], font=FONT_MAIN)
    btn_copy_key.configure(bg=c["btn_dark"], fg="white", font=FONT_MAIN)
    btn_rand_key.configure(bg=c["btn_secondary"], fg="white", font=FONT_BOLD)
    btn_key_manager.configure(bg=c["btn_dark"], fg="white", font=FONT_MAIN)
    
    tab_text_frame.configure(bg=c["card"])
    tab_file_frame.configure(bg=c["card"])
    lbl_input.configure(bg=c["card"], fg=c["text"], font=FONT_BOLD)
    text_entry.configure(bg=c["input"], fg="#ffffff", insertbackground="white", font=FONT_MAIN)
    btn_paste.configure(bg=c["btn_dark"], fg=c["accent"], font=FONT_BOLD)
    btn_frame.configure(bg=c["card"])
    encrypt_btn.configure(bg=c["btn_primary"], fg="white", font=FONT_BOLD)
    decrypt_btn.configure(bg=c["btn_secondary"], fg="white", font=FONT_BOLD)
    clear_btn.configure(bg=c["btn_dark"], fg="white", font=FONT_MAIN)
    lbl_output.configure(bg=c["card"], fg=c["text"], font=FONT_BOLD)
    result_entry.configure(bg=c["input"], fg=c["accent"], insertbackground="white", font=FONT_CODE)
    btn_copy_output.configure(bg="#238636", fg="white", font=FONT_BOLD)
    
    lbl_file.configure(bg=c["card"], fg=c["text"], font=FONT_BOLD)
    drop_zone_box.configure(bg=c["input"], fg=c["accent"])
    btn_select_file.configure(bg=c["card"], fg=c["accent"], font=FONT_BOLD)
    lbl_file_status.configure(bg=c["input"], font=FONT_MAIN)
    file_btn_frame.configure(bg=c["card"])
    btn_enc_file.configure(bg=c["btn_primary"], fg="white", font=FONT_BOLD)
    btn_dec_file.configure(bg=c["btn_secondary"], fg="white", font=FONT_BOLD)
    
    log_title_frame.configure(bg=c["bg"])
    lbl_log.configure(bg=c["bg"], fg=c["muted"], font=FONT_BOLD)
    btn_clear_log.configure(bg=c["btn_dark"], fg="white", font=FONT_MAIN)
    log_box.configure(bg="#010409", fg=c["accent"], font=("Consolas", 8))
    status_label.configure(bg=c["bg"], fg=c["accent"], font=FONT_MAIN)
    
    style.configure("TNotebook", background=c["bg"], borderwidth=0)
    style.configure("TNotebook.Tab", background=c["card"], foreground=c["text"], padding=[15, 6], font=FONT_BOLD)
    style.map("TNotebook.Tab", background=[("selected", c["accent"])], foreground=[("selected", "#000000")])
    style.configure("Horizontal.TProgressbar", troughcolor=c["input"], background=c["accent"])
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
    q = "آیا از پاک کردن کامل تاریخچه مطمئن هستید؟" if current_lang == "fa" else "Clear all logs?"
    if not messagebox.askyesno("تایید", q): return
    log_box.config(state="normal")
    log_box.delete("1.0", tk.END)
    log_box.config(state="disabled")
    status_label.config(text="تاریخچه پاکسازی شد" if current_lang == "fa" else "Logs cleared", fg="green")

def update_log_button_ui():
    if logs_enabled: btn_toggle_log.config(text=LANGUAGES[current_lang]["log_active"], bg="#238636", fg="white", font=FONT_MAIN)
    else: btn_toggle_log.config(text=LANGUAGES[current_lang]["log_inactive"], bg="#da3633", fg="white", font=FONT_MAIN)

def change_language(lang):
    global current_lang
    current_lang = lang
    save_config_file()
    root.title(LANGUAGES[lang]["title"])
    protocol_label.config(text=LANGUAGES[lang]["protocol"])
    menu_btn.config(text=LANGUAGES[lang]["settings_menu"])
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
    
    menu.entryconfigure(0, label=f"{'نسخه برنامه' if lang == 'fa' else 'App Version'}: {CURRENT_VERSION}")
    menu.entryconfigure(1, label=LANGUAGES[lang]["menu_help"])
    menu.entryconfigure(2, label=LANGUAGES[lang]["menu_update"])
    menu.entryconfigure(3, label=LANGUAGES[lang]["menu_changelog"])
    
    update_log_button_ui()
    status_label.config(text=LANGUAGES[lang]["status_online"])
    apply_theme()

def show_menu(): menu.post(menu_btn.winfo_rootx(), menu_btn.winfo_rooty() + menu_btn.winfo_height())

def check_for_updates():
    status_label.config(text="در حال بررسی آپدیت..." if current_lang == "fa" else "Checking update...", fg="#ffa500")
    add_log("Checking update server...")
    threading.Thread(target=thread_update_logic, daemon=True).start()

def thread_update_logic():
    try:
        headers = {'User-Agent': 'Mozilla/5.0'}
        req = urllib.request.Request(VERSION_URL, headers=headers)
        with urllib.request.urlopen(req, timeout=10) as response:
            latest_version = response.read().decode('utf-8').strip()
        if latest_version > CURRENT_VERSION:
            root.after(0, lambda: ask_for_download(latest_version))
        else:
            root.after(0, lambda: [messagebox.showinfo("آپدیت", "برنامه شما به‌روز است!" if current_lang == "fa" else "Your application is up to date!"), add_log("System is up to date.")])
            root.after(0, lambda: status_label.config(text=LANGUAGES[current_lang]["status_online"]))
    except urllib.error.HTTPError as e:
        if e.code == 404:
            err_msg = "فایل نسخه در گیت‌هاب یافت نشد (خطای 404).\nلطفاً مطمئن شوید فایل version.txt در ریپوزیتوری گیت‌هاب موجود است." if current_lang == "fa" else "Version file not found on GitHub (404 Error)."
        else:
            err_msg = f"خطای شبکه HTTP {e.code}"
        root.after(0, lambda: [messagebox.showerror("خطای آپدیت", err_msg), add_log("Update check failed (404)."), status_label.config(text=LANGUAGES[current_lang]["status_online"])])
    except Exception as e:
        error_msg = str(e)
        root.after(0, lambda: [messagebox.showerror("خطا", f"خطا در اتصال به سرور:\n{error_msg}"), add_log("Update check failed."), status_label.config(text=LANGUAGES[current_lang]["status_online"])])

def ask_for_download(new_version):
    msg = f"نسخه جدید {new_version} موجود است. آیا مایلید خودکار دریافت و نصب شود؟" if current_lang == "fa" else f"New version {new_version} available. Download and update?"
    if messagebox.askyesno("آپدیت جدید", msg):
        status_label.config(text="در حال دریافت فایل آپدیت...", fg="#ffa500")
        add_log(f"Downloading v{new_version}...")
        threading.Thread(target=lambda: thread_download_overhauled(new_version), daemon=True).start()

def thread_download_overhauled(new_version):
    try:
        current_exe_path = os.path.abspath(sys.argv[0])
        headers = {'User-Agent': 'Mozilla/5.0'}
        if current_exe_path.endswith(".py"):
            source_url = "https://raw.githubusercontent.com/amirjkkjhk-ux/Anigma-Modern/main/Anigma_Modern.py"
            req = urllib.request.Request(source_url, headers=headers)
            with urllib.request.urlopen(req, timeout=30) as response:
                new_code = response.read()
            with open(current_exe_path, "wb") as f:
                f.write(new_code)
            root.after(0, lambda: messagebox.showinfo("موفقیت", "برنامه به نسخه جدید ارتقا یافت!"))
            return
    except Exception as e:
        root.after(0, lambda: messagebox.showerror("خطا", f"خطا در آپدیت: {str(e)}"))

def open_help():
    help_window = tk.Toplevel(root)
    help_window.title(LANGUAGES[current_lang]["help_title"])
    help_window.geometry("580x560")
    c = THEMES["night"]
    help_window.configure(bg=c["card"])
    
    title_frame = tk.LabelFrame(help_window, text=f" {LANGUAGES[current_lang]['help_dev_info']} ", bg=c["card"], fg=c["accent"], font=FONT_TITLE)
    title_frame.pack(fill="x", padx=15, pady=8)
    
    tk.Label(title_frame, text="امیر مهدی بساوند (Amir Mehdi Basavand)", bg=c["card"], fg=c["btn_primary"], font=FONT_BOLD).pack(pady=2)
    tk.Label(title_frame, text="ایمیل: amirjkkjhk@gmail.com | تلگرام: @Amirshoq", bg=c["card"], fg="gray", font=FONT_CODE).pack(pady=2)

    intro_frame = tk.LabelFrame(help_window, text=f" {LANGUAGES[current_lang]['help_app_intro_title']} ", bg=c["card"], fg=c["accent"], font=FONT_TITLE)
    intro_frame.pack(fill="x", padx=15, pady=6)
    
    intro_text = tk.Text(intro_frame, bg=c["input"], fg="white", wrap="word", font=FONT_MAIN, bd=0, height=5)
    intro_text.pack(fill="both", expand=True, padx=5, pady=5)
    intro_text.insert("1.0", LANGUAGES[current_lang]["help_app_intro_text"])
    intro_text.config(state="disabled")

    guide_frame = tk.LabelFrame(help_window, text=f" {LANGUAGES[current_lang]['help_usage_title']} ", bg=c["card"], fg=c["accent"], font=FONT_TITLE)
    guide_frame.pack(fill="both", expand=True, padx=15, pady=8)
    
    guide_text = tk.Text(guide_frame, bg=c["input"], fg="white", wrap="word", font=FONT_MAIN, bd=0)
    guide_text.pack(fill="both", expand=True, padx=5, pady=5)
    guide_text.insert("1.0", LANGUAGES[current_lang]["help_usage_text"])
    guide_text.config(state="disabled")

def open_changelog():
    changelog_window = tk.Toplevel(root)
    changelog_window.title(LANGUAGES[current_lang]["changelog_title"])
    changelog_window.geometry("520x350")
    c = THEMES["night"]
    changelog_window.configure(bg=c["card"])
    
    frame = tk.LabelFrame(changelog_window, text=f" {LANGUAGES[current_lang]['changelog_title']} ", bg=c["card"], fg=c["accent"], font=FONT_TITLE)
    frame.pack(fill="both", expand=True, padx=15, pady=12)
    
    text_area = tk.Text(frame, bg=c["input"], fg="white", wrap="word", font=FONT_MAIN, bd=0)
    text_area.pack(fill="both", expand=True, padx=8, pady=8)
    text_area.insert("1.0", LANGUAGES[current_lang]["changelog_text"])
    text_area.config(state="disabled")

def open_key_manager():
    if not unlock_key_manager(): return

    def refresh_list():
        listbox.delete(0, tk.END)
        for name in saved_keys: listbox.insert(tk.END, name)
    def add_new_key():
        n, v = name_entry.get().strip(), val_entry.get().strip()
        if n and v:
            saved_keys[n] = v
            persist_saved_keys()
            refresh_list()
            name_entry.delete(0, tk.END)
            val_entry.delete(0, tk.END)
            add_log(f"Key saved: '{n}'")
    def delete_key():
        try:
            target = listbox.get(listbox.curselection())
            del saved_keys[target]
            persist_saved_keys()
            refresh_list()
            add_log(f"Key deleted: '{target}'")
        except Exception: pass
    def select_key(e):
        try:
            key_entry.delete(0, tk.END)
            key_entry.insert(0, saved_keys[listbox.get(listbox.curselection())])
            check_key_strength()
            add_log("Key loaded from manager.")
            on_close()
        except Exception: pass
    def on_close():
        lock_key_manager()
        manager_win.destroy()

    c = THEMES["night"]
    manager_win = tk.Toplevel(root)
    manager_win.geometry("420x460")
    manager_win.title("مدیریت کلیدها" if current_lang == "fa" else "Key Manager")
    manager_win.configure(bg=c["card"])
    manager_win.protocol("WM_DELETE_WINDOW", on_close)
    
    header_frame = tk.LabelFrame(manager_win, text=" راهنمای بخش مدیریت کلیدها " if current_lang == "fa" else " Key Manager Guide ", bg=c["card"], fg=c["accent"], font=FONT_TITLE)
    header_frame.pack(fill="x", padx=12, pady=10)
    
    guide_text = "کلیدهای امنیتی خود را با نام دلخواه ذخیره کنید. با دوبار کلیک روی هر کلید، مستقیماً وارد فرم اصلی می‌شود." if current_lang == "fa" else "Save your secret keys securely. Double-click any key to load it into the main form."
    tk.Label(header_frame, text=guide_text, bg=c["card"], fg=c["text"], font=FONT_MAIN, wraplength=380, justify="left").pack(padx=8, pady=6)

    listbox = tk.Listbox(manager_win, bg=c["input"], fg=c["accent"], font=FONT_CODE, bd=1, relief="solid")
    listbox.pack(fill="both", expand=True, padx=12, pady=5)
    listbox.bind('<Double-1>', select_key)
    refresh_list()
    
    f = tk.Frame(manager_win, bg=c["card"])
    f.pack(fill="x", padx=12, pady=5)
    name_entry = tk.Entry(f, width=12, bg=c["input"], fg="white", insertbackground="white", font=FONT_MAIN)
    name_entry.pack(side="left", padx=2, ipady=3)
    val_entry = tk.Entry(f, width=18, bg=c["input"], fg="white", insertbackground="white", font=FONT_MAIN)
    val_entry.pack(side="left", padx=2, ipady=3)
    
    tk.Button(f, text="+ افزودن" if current_lang == "fa" else "+ Add", command=add_new_key, bg=c["btn_secondary"], fg="white", font=FONT_BOLD, bd=0, cursor="hand2").pack(side="right", padx=2, ipady=2)
    tk.Button(manager_win, text="حذف کلید انتخابی" if current_lang == "fa" else "Delete Key", command=delete_key, bg=c["btn_primary"], fg="white", font=FONT_BOLD, bd=0, cursor="hand2").pack(fill="x", padx=12, pady=(4, 12), ipady=3)

def drop_inside_file_zone(event):
    global selected_file_path
    p = event.data
    if p.startswith('{'): p = p[1:-1]
    if os.path.exists(p):
        selected_file_path = p
        update_file_label()
        add_log(f"File loaded: {os.path.basename(p)}")

def select_file():
    global selected_file_path
    p = filedialog.askopenfilename()
    if p:
        selected_file_path = p
        update_file_label()
        add_log(f"File selected: {os.path.basename(p)}")

def update_file_label():
    c = THEMES["night"]
    if selected_file_path:
        size_mb = os.path.getsize(selected_file_path) / (1024 * 1024)
        lbl_file_status.config(text=f"{os.path.basename(selected_file_path)} ({size_mb:.2f} MB)", fg=c["accent"])
    else:
        lbl_file_status.config(text=LANGUAGES[current_lang]["file_not_selected"], fg=c["muted"])

def set_buttons_state(state):
    btn_enc_file.config(state=state)
    btn_dec_file.config(state=state)
    btn_select_file.config(state=state)

def start_file_thread(action):
    if not selected_file_path or not key_entry.get(): 
        messagebox.showwarning("هشدار" if current_lang == "fa" else "Warning", LANGUAGES[current_lang]["warning_no_file"])
        return
    status_label.config(text=LANGUAGES[current_lang]["processing"], fg="#ffa500")
    set_buttons_state("disabled")
    progress_bar["value"] = 0
    if action == "encrypt": threading.Thread(target=process_encrypt_file, daemon=True).start()
    else: threading.Thread(target=process_decrypt_file, daemon=True).start()

def process_encrypt_file():
    try:
        salt = get_random_bytes(SALT_SIZE)
        key = derive_key(key_entry.get(), salt)
        cipher = AES.new(key, AES.MODE_GCM)
        compressor = zlib.compressobj()

        total_size = os.path.getsize(selected_file_path)
        out = selected_file_path + ".anigma"
        chunk_size = 64 * 1024
        read_bytes = 0

        with open(out, "wb") as fout:
            fout.write(salt + cipher.nonce)
            with open(selected_file_path, "rb") as fin:
                while True:
                    chunk = fin.read(chunk_size)
                    if not chunk: break
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
        root.after(0, lambda: [messagebox.showerror("خطا", str(e)), status_label.config(text=LANGUAGES[current_lang]["status_online"])])
    finally:
        root.after(0, lambda: set_buttons_state("normal"))

def process_decrypt_file():
    tmp_out = None
    try:
        total_file_size = os.path.getsize(selected_file_path)
        ciphertext_len = total_file_size - SALT_SIZE - 16 - 16
        if ciphertext_len < 0: raise Exception("فایل آسیب دیده است." if current_lang == "fa" else "Corrupted file.")

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
            with open(tmp_out, "wb") as fout:
                while remaining > 0:
                    chunk = f.read(min(chunk_size, remaining))
                    if not chunk: break
                    remaining -= len(chunk)
                    read_total += len(chunk)
                    plain_chunk = decompressor.decompress(cipher.decrypt(chunk))
                    if plain_chunk: fout.write(plain_chunk)
                    progress = int((read_total / ciphertext_len) * 100) if ciphertext_len else 100
                    root.after(0, lambda p=progress: progress_bar.configure(value=p))
                fout.write(decompressor.flush())

            tag = f.read(16)
            cipher.verify(tag)

        os.replace(tmp_out, out)
        tmp_out = None
        root.after(0, lambda: file_success_ui(out, "dec"))
    except Exception:
        root.after(0, lambda: [messagebox.showerror("خطا", LANGUAGES[current_lang]["error_decrypt"]), status_label.config(text=LANGUAGES[current_lang]["status_online"])])
    finally:
        if tmp_out and os.path.exists(tmp_out):
            try: os.remove(tmp_out)
            except Exception: pass
        root.after(0, lambda: set_buttons_state("normal"))

def file_success_ui(p, mode): 
    msg = f"عملیات با موفقیت انجام شد:\n{os.path.basename(p)}" if current_lang == "fa" else f"Operation successful:\n{os.path.basename(p)}"
    messagebox.showinfo("موفقیت" if current_lang == "fa" else "Success", msg)
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
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
    secure_key = "".join(secrets.choice(alphabet) for _ in range(16))
    key_entry.delete(0, tk.END)
    key_entry.insert(0, secure_key)
    check_key_strength()
    add_log("New random key generated.")

def check_key_strength(e=None):
    k = key_entry.get()
    if not k: strength_label.config(text=LANGUAGES[current_lang]["key_empty"], fg="gray")
    elif len(k) < 6: strength_label.config(text=LANGUAGES[current_lang]["key_weak"], fg="#ff0055")
    elif len(k) < 12: strength_label.config(text=LANGUAGES[current_lang]["key_good"], fg="#ffa500")
    else: strength_label.config(text=LANGUAGES[current_lang]["key_military"], fg="#00f0ff")

def encode_message():
    txt, k = text_entry.get("1.0", tk.END).strip(), key_entry.get().strip()
    if not txt or not k: 
        messagebox.showwarning("هشدار" if current_lang == "fa" else "Warning", LANGUAGES[current_lang]["warning_empty"])
        return
    try:
        salt = get_random_bytes(SALT_SIZE)
        key = derive_key(k, salt)
        cipher = AES.new(key, AES.MODE_GCM)
        ctx, tag = cipher.encrypt_and_digest(txt.encode('utf-8'))
        result_entry.delete("1.0", tk.END); result_entry.insert("1.0", base64.urlsafe_b64encode(salt + cipher.nonce + tag + ctx).decode('utf-8'))
        status_label.config(text=LANGUAGES[current_lang]["status_encrypted"], fg="green")
        add_log("Text encryption successful.")
    except Exception as e: messagebox.showerror("خطا", str(e))

def decode_message():
    ctx, k = text_entry.get("1.0", tk.END).strip(), key_entry.get().strip()
    if not ctx or not k: 
        messagebox.showwarning("هشدار" if current_lang == "fa" else "Warning", LANGUAGES[current_lang]["warning_empty"])
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
        messagebox.showerror("خطا" if current_lang == "fa" else "Error", LANGUAGES[current_lang]["error_decrypt"])

def clear_all(): 
    text_entry.delete("1.0", tk.END); key_entry.delete(0, tk.END); result_entry.delete("1.0", tk.END)
    status_label.config(text=LANGUAGES[current_lang]["status_cleared"], fg="gray")

load_config()

if HAS_DND:
    root = TkinterDnD.Tk()
else:
    root = tk.Tk()

root.geometry("640x720") 
root.resizable(False, False)
style = ttk.Style()
style.theme_use('default')

# هدر بالا
top_bar = tk.Frame(root)
top_bar.pack(fill="x", padx=15, pady=8)

menu_btn = tk.Button(top_bar, bd=0, cursor="hand2", padx=10, pady=3)
menu_btn.pack(side="left")

protocol_label = tk.Label(top_bar)
protocol_label.pack(side="right")

# بخش کلید امنیتی
global_key_frame = tk.Frame(root, bd=0)
global_key_frame.pack(fill="x", padx=20, pady=5)

key_title_frame = tk.Frame(global_key_frame)
key_title_frame.pack(fill="x", padx=10, pady=(10, 4))

lbl_key = tk.Label(key_title_frame)
lbl_key.pack(side="left")

strength_label = tk.Label(key_title_frame)
strength_label.pack(side="right")

key_entry = tk.Entry(global_key_frame, show="*", bd=1, relief="solid")
key_entry.pack(fill="x", padx=10, pady=4, ipady=4)
key_entry.bind("<KeyRelease>", check_key_strength)

key_opt_frame = tk.Frame(global_key_frame)
key_opt_frame.pack(fill="x", padx=10, pady=(4, 10))

show_key_var = tk.BooleanVar()
show_key_btn = tk.Checkbutton(key_opt_frame, variable=show_key_var, command=toggle_password_visibility, cursor="hand2")
show_key_btn.pack(side="left")

btn_key_manager = tk.Button(key_opt_frame, command=open_key_manager, bd=0, cursor="hand2")
btn_key_manager.pack(side="right", padx=2, ipadx=8, ipady=3)

btn_rand_key = tk.Button(key_opt_frame, command=generate_random_key, bd=0, cursor="hand2")
btn_rand_key.pack(side="right", padx=2, ipadx=8, ipady=3)

btn_copy_key = tk.Button(key_opt_frame, command=copy_key, bd=0, cursor="hand2")
btn_copy_key.pack(side="right", padx=2, ipadx=8, ipady=3)

# تب‌ها
notebook = ttk.Notebook(root)
notebook.pack(fill="both", expand=True, padx=20, pady=10)

tab_text_frame = tk.Frame(notebook)
tab_file_frame = tk.Frame(notebook)
notebook.add(tab_text_frame)
notebook.add(tab_file_frame)

# تب متن
lbl_input = tk.Label(tab_text_frame)
lbl_input.pack(anchor="w", padx=12, pady=(10, 2))

text_entry = tk.Text(tab_text_frame, height=3, bd=1, relief="solid")
text_entry.pack(fill="x", padx=12, pady=2)

btn_paste = tk.Button(tab_text_frame, command=paste_input, bd=0, cursor="hand2")
btn_paste.pack(fill="x", padx=12, pady=4, ipady=3)

btn_frame = tk.Frame(tab_text_frame)
btn_frame.pack(fill="x", padx=12, pady=6)

encrypt_btn = tk.Button(btn_frame, command=encode_message, bd=0, cursor="hand2")
encrypt_btn.pack(side="left", fill="x", expand=True, padx=(0, 2), ipady=5)

decrypt_btn = tk.Button(btn_frame, command=decode_message, bd=0, cursor="hand2")
decrypt_btn.pack(side="left", fill="x", expand=True, padx=2, ipady=5)

clear_btn = tk.Button(btn_frame, command=clear_all, bd=0, cursor="hand2")
clear_btn.pack(side="right", fill="x", expand=True, padx=(2, 0), ipady=5)

lbl_output = tk.Label(tab_text_frame)
lbl_output.pack(anchor="w", padx=12, pady=(6, 2))

result_entry = tk.Text(tab_text_frame, height=3, bd=1, relief="solid")
result_entry.pack(fill="x", padx=12, pady=2)

btn_copy_output = tk.Button(tab_text_frame, command=copy_output, bd=0, cursor="hand2")
btn_copy_output.pack(fill="x", padx=12, pady=(4, 10), ipady=4)

# تب فایل
lbl_file = tk.Label(tab_file_frame)
lbl_file.pack(anchor="w", padx=12, pady=(10, 4))

drop_zone_box = tk.LabelFrame(tab_file_frame, bd=1, relief="solid")
drop_zone_box.pack(fill="x", padx=12, pady=5, ipady=10)

if HAS_DND:
    drop_zone_box.drop_target_register(DND_FILES)
    drop_zone_box.dnd_bind('<<Drop>>', drop_inside_file_zone)

btn_select_file = tk.Button(drop_zone_box, command=select_file, bd=1, relief="solid", cursor="hand2")
btn_select_file.pack(pady=4, ipadx=10, ipady=2)

lbl_file_status = tk.Label(drop_zone_box)
lbl_file_status.pack(pady=2)

file_btn_frame = tk.Frame(tab_file_frame)
file_btn_frame.pack(fill="x", padx=12, pady=10)

btn_enc_file = tk.Button(file_btn_frame, command=lambda: start_file_thread("encrypt"), bd=0, cursor="hand2")
btn_enc_file.pack(side="left", fill="x", expand=True, padx=(0, 4), ipady=5)

btn_dec_file = tk.Button(file_btn_frame, command=lambda: start_file_thread("decrypt"), bd=0, cursor="hand2")
btn_dec_file.pack(side="right", fill="x", expand=True, padx=(4, 0), ipady=5)

progress_bar = ttk.Progressbar(tab_file_frame, orient="horizontal", mode="determinate")
progress_bar.pack(fill="x", padx=12, pady=5)

# کنسول لاگ
log_title_frame = tk.Frame(root)
log_title_frame.pack(fill="x", padx=20, pady=(2, 0))

lbl_log = tk.Label(log_title_frame)
lbl_log.pack(side="right")

btn_toggle_log = tk.Button(log_title_frame, command=toggle_logs, bd=0, cursor="hand2")
btn_toggle_log.pack(side="left", padx=2)

btn_clear_log = tk.Button(log_title_frame, command=clear_logs_action, bd=0, cursor="hand2")
btn_clear_log.pack(side="left", padx=2)

log_container = tk.Frame(root)
log_container.pack(fill="x", padx=20, pady=2)

scrollbar_y = tk.Scrollbar(log_container, orient="vertical")
scrollbar_y.pack(side="right", fill="y")

log_box = tk.Text(log_container, height=3, bd=1, relief="solid", state="disabled", yscrollcommand=scrollbar_y.set)
log_box.pack(side="left", fill="both", expand=True)
scrollbar_y.config(command=log_box.yview)

status_label = tk.Label(root)
status_label.pack(side="bottom", pady=6)

# منوی اصلی
menu = tk.Menu(root, tearoff=0)
menu.add_command(label=f"نسخه برنامه: {CURRENT_VERSION}", state="disabled")
menu.add_command(label=LANGUAGES[current_lang]["menu_help"], command=open_help)
menu.add_command(label=LANGUAGES[current_lang]["menu_update"], command=check_for_updates)
menu.add_command(label=LANGUAGES[current_lang]["menu_changelog"], command=open_changelog)

lang_menu = tk.Menu(menu, tearoff=0)
lang_menu.add_command(label="فارسی", command=lambda: change_language("fa"))
lang_menu.add_command(label="English", command=lambda: change_language("en"))
menu.add_cascade(label="Language / زبان", menu=lang_menu)

menu_btn.config(command=show_menu)

change_language(current_lang)
add_log("Anigma Core Engine initialized.")
root.mainloop()
