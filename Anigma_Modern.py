# DEVELOPER: Amir Mehdi Basavand (امیر مهدی بساوند)
# EMAIL: amirjkkjhk@gmail.com
# TELEGRAM ID: @Amirshoq
# ====================================================================================
# PROJECT: ANIGMA MODERN | VERSION: 15.0 (Live Smart Auto-Update EXE)
# ====================================================================================

import tkinter as tk
from tkinter import messagebox, ttk, filedialog
from tkinterdnd2 import TkinterDnD, DND_FILES 
import base64
import hashlib
import random
import string
import os
import sys
import zlib
import threading
import json
import subprocess
from datetime import datetime
import urllib.request 
from Crypto.Cipher import AES 

CONFIG_FILE = "config.json"
CURRENT_VERSION = "15.0"

VERSION_URL = "https://raw.githubusercontent.com/amirjkkjhk-ux/Anigma-Modern/refs/heads/main/version.txt.txt"
# نکته: این لینک باید مستقیماً به فایل Anigma_Modern.exe کامپایل شده در گیت‌هاب اشاره کند
UPDATE_URL = "https://raw.githubusercontent.com/amirjkkjhk-ux/Anigma-Modern/refs/heads/main/Anigma_Modern.exe"

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
saved_keys = {}  

def load_config():
    global current_lang, logs_enabled, saved_keys, current_theme
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r") as f:
                config = json.load(f)
                if config.get("language") in LANGUAGES: current_lang = config["language"]
                if config.get("theme") in THEMES: current_theme = config["theme"]
                if "logs_enabled" in config: logs_enabled = config["logs_enabled"]
                if "saved_keys" in config:
                    encoded_dict = config["saved_keys"]
                    saved_keys = {k: base64.b64decode(v.encode()).decode('utf-8') for k, v in encoded_dict.items()}
        except: pass

def save_config_file():
    try:
        encoded_dict = {k: base64.b64encode(v.encode()).decode('utf-8') for k, v in saved_keys.items()}
        with open(CONFIG_FILE, "w") as f:
            json.dump({"language": current_lang, "theme": current_theme, "logs_enabled": logs_enabled, "saved_keys": encoded_dict}, f)
    except: pass

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
    now = datetime.now().strftime("%Y-%b-%d %H:%M:%S")
    log_box.config(state="normal")
    log_box.insert(tk.END, f"[{now}] ", "ltr_log")
    if current_lang == "fa": log_box.insert(tk.END, f"\u200f{message}\n", "rtl_log")
    else: log_box.insert(tk.END, f"{message}\n", "ltr_log")
    log_box.see(tk.END)
    log_box.config(state="disabled")

def toggle_logs():
    global logs_enabled
    logs_enabled = not logs_enabled
    save_config_file()
    update_log_button_ui()

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
    update_log_button_ui()
    status_label.config(text=LANGUAGES[lang]["status_online"])
    apply_theme(current_theme)

def show_menu(): menu.post(menu_btn.winfo_rootx(), menu_btn.winfo_rooty() + menu_btn.winfo_height())

def check_for_updates():
    status_label.config(text="در حال بررسی آپدیت..." if current_lang == "fa" else "Checking update...", fg="#ffa500")
    threading.Thread(target=thread_update_logic, daemon=True).start()

def thread_update_logic():
    try:
        req = urllib.request.Request(VERSION_URL, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=5) as response:
            latest_version = response.read().decode('utf-8').strip()
        if latest_version > CURRENT_VERSION:
            root.after(0, lambda: ask_for_download(latest_version))
        else:
            root.after(0, lambda: messagebox.showinfo("UPDATE", "برنامه شما به‌روز است!"))
            root.after(0, lambda: status_label.config(text=LANGUAGES[current_lang]["status_online"]))
    except Exception as e:
        root.after(0, lambda: messagebox.showerror("ERROR", f"خطا در اتصال به سرور:\n{e}"))

def ask_for_download(new_version):
    msg = f"نسخه جدید {new_version} در دسترس است. آیا مایلید به صورت خودکار دانلود و نصب شود؟"
    if messagebox.askyesno("NEW UPDATE AVAILABLE", msg):
        status_label.config(text="در حال دریافت آپدیت...", fg="#ffa500")
        threading.Thread(target=thread_download_new_version, daemon=True).start()

def thread_download_new_version():
    try:
        req = urllib.request.Request(UPDATE_URL, headers={'User-Agent': 'Mozilla/5.0'})
        current_exe_or_py = os.path.abspath(sys.argv[0])
        working_dir = os.path.dirname(current_exe_or_py)
        
        # اگر سورس پایتون در حال اجراست
        if current_exe_or_py.endswith(".py"):
            with urllib.request.urlopen(req, timeout=25) as response:
                new_code = response.read()
            with open(current_exe_or_py, "wb") as f:
                f.write(new_code)
            root.after(0, lambda: messagebox.showinfo("SUCCESS", "سورس پایتون با موفقیت آپدیت شد."))
            return
            
        # اگر فایل EXE در حال اجراست (دانلود مستقیم فایل کامپایل شده بدون نیاز به کمپایلر سیستم)
        temp_new_exe = os.path.join(working_dir, "_new_version_.exe")
        
        with urllib.request.urlopen(req, timeout=40) as response:
            with open(temp_new_exe, "wb") as f:
                f.write(response.read())
            
        bat_path = os.path.join(working_dir, "updater.bat")
        
        # ساخت یک اسکریپت جایگزینی مستقل بدون وابستگی به پوشه موقت AppData
        with open(bat_path, "w", encoding="utf-8") as b:
            b.write('@echo off\n')
            b.write('timeout /t 2 /nobreak > nul\n')
            b.write(f'cd /d "{working_dir}"\n')
            b.write(f'del /f /q "{current_exe_or_py}"\n')
            b.write(f'move /y "_new_version_.exe" "{current_exe_or_py}"\n')
            b.write(f'start "" "{current_exe_or_py}"\n')
            b.write('del "%~f0"\n')
            
        root.after(0, lambda: messagebox.showinfo("EXE UPDATE", "نسخه جدید با موفقیت دانلود شد. برنامه جهت اعمال تغییرات بسته و مجدداً باز خواهد شد."))
        
        subprocess.Popen([bat_path], shell=True, cwd=working_dir, creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
        root.quit()
        sys.exit(0)
        
    except Exception as e:
        root.after(0, lambda: messagebox.showerror("DOWNLOAD ERROR", f"خطا در فرآیند جایگزینی فایل:\n{e}"))

def open_help():
    help_window = tk.Toplevel(root)
    help_window.title("ABOUT & USER GUIDE")
    help_window.geometry("520x540")
    help_window.configure(bg=THEMES[current_theme]["card"])
    
    title_frame = tk.LabelFrame(help_window, text=" شناسنامه سازنده پروژه ", bg=help_window["bg"], fg=THEMES[current_theme]["accent"], font=("Segoe UI", 10, "bold"))
    title_frame.pack(fill="x", padx=15, pady=10)
    
    tk.Label(title_frame, text="توسعه دهنده و مالک اصلی آنیگما مدرن:", bg=help_window["bg"], fg="white", font=("Segoe UI", 10)).pack(pady=2)
    tk.Label(title_frame, text="امیر مهدی بساوند (Amir Mehdi Basavand)", bg=help_window["bg"], fg=THEMES[current_theme]["btn_primary"], font=("Segoe UI", 12, "bold")).pack(pady=2)
    tk.Label(title_frame, text="📬 ایمیل: amirjkkjhk@gmail.com  |  ✈️ تلگرام: @Amirshoq", bg=help_window["bg"], fg="gray", font=("Consolas", 10)).pack(pady=4)

    guide_frame = tk.LabelFrame(help_window, text=" راهنمای کامل استفاده از برنامه ", bg=help_window["bg"], fg=THEMES[current_theme]["accent"], font=("Segoe UI", 10, "bold"))
    guide_frame.pack(fill="both", expand=True, padx=15, pady=10)
    
    text_area = tk.Text(guide_frame, bg=THEMES[current_theme]["input"], fg="white", wrap="word", font=("Segoe UI", 10), bd=0)
    text_area.pack(fill="both", expand=True, padx=5, pady=5)
    
    guide_text = (
        "۱. بخش رمزگذاری متنی:\n"
        "   - ابتدا در باکس شماره ۱ متن خود را تایپ کنید یا دکمه PASTE را بزنید.\n"
        "   - یک کلید امنیتی (Secret Key) وارد کنید یا روی تولید کلید تصادفی کلیک کنید.\n"
        "   - دکمه 'رمزگذاری متنی' را بزنید. متن قفل شده در باکس ۲ ظاهر می‌شود.\n"
        "   - برای باز کردن، متن قفل شده را در باکس ۱ گذاشته، کلید اصلی را بزنید و دکمه 'رمزگشایی متنی' را فشار دهید.\n\n"
        "۲. بخش رمزگذاری فایل ها (فوق امنیتی):\n"
        "   - به تب قفل‌گذاری فایل بروید.\n"
        "   - فایل مورد نظر خود را با دکمه انتخاب کنید یا آن را مستقیم بکشید و داخل کادر رها کنید (Drag & Drop).\n"
        "   - رمز عبور خود را وارد کرده و دکمه 'رمزگذاری فایل' را بزنید. فایلی با پسوند .anigma در کنار فایل شما ساخته می‌شود.\n"
        "   - برای باز کردن فایل، همان فایل .anigma را انتخاب کرده، رمز صحیح را وارد کنید و دکمه 'رمزگشایی فایل' را بزنید.\n\n"
        "۳. سیستم مدیریت کلیدها:\n"
        "   - با کلیک روی 'مدیریت کلیدها' می‌توانید کلیدهای پرکاربرد خود را با نام دلخواه ذخیره کنید تا هر بار نیاز به تایپ مجدد نباشد.\n\n"
        "۴. سیستم آپدیت خودکار آنلاین کاربران معمولی:\n"
        "   - از منوی اصلی روی 'بررسی آپدیت آنلاین' کلیک کنید. سیستم بدون نیاز به دانش فنی فایل EXE را به طور خودکار در بک‌گراند آپدیت و راه‌اندازی مجدد می‌کند."
    )
    text_area.insert("1.0", guide_text)
    text_area.config(state="disabled")

def open_key_manager():
    def refresh_list():
        listbox.delete(0, tk.END)
        for name in saved_keys: listbox.insert(tk.END, name)
    def add_new_key():
        n, v = name_entry.get().strip(), val_entry.get().strip()
        if n and v: saved_keys[n] = v; save_config_file(); refresh_list()
    def delete_key():
        try: del saved_keys[listbox.get(listbox.curselection())]; save_config_file(); refresh_list()
        except: pass
    def select_key(e):
        try: key_entry.delete(0, tk.END); key_entry.insert(0, saved_keys[listbox.get(listbox.curselection())]); check_key_strength(); manager_win.destroy()
        except: pass

    manager_win = tk.Toplevel(root)
    manager_win.geometry("360x420")
    manager_win.configure(bg=THEMES[current_theme]["card"])
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
    if os.path.exists(p): selected_file_path = p; update_file_label()

def select_file():
    global selected_file_path
    p = filedialog.askopenfilename()
    if p: selected_file_path = p; update_file_label()

def update_file_label():
    c = THEMES[current_theme]
    lbl_file_status.config(text=os.path.basename(selected_file_path) if selected_file_path else "فایلی انتخاب نشده", fg=c["accent"] if selected_file_path else c["muted"])

def start_file_thread(action):
    if not selected_file_path or not key_entry.get(): return
    if action == "encrypt": threading.Thread(target=process_encrypt_file).start()
    else: threading.Thread(target=process_decrypt_file).start()

def process_encrypt_file():
    try:
        k = hashlib.sha256(key_entry.get().encode()).digest()
        with open(selected_file_path, "rb") as f: d = f.read()
        cipher = AES.new(k, AES.MODE_GCM)
        ctx, tag = cipher.encrypt_and_digest(zlib.compress(d))
        out = selected_file_path + ".anigma"
        with open(out, "wb") as f: f.write(cipher.nonce + tag + ctx)
        root.after(0, lambda: file_success_ui(out))
    except Exception as e: root.after(0, lambda: messagebox.showerror("ERROR", str(e)))

def process_decrypt_file():
    try:
        k = hashlib.sha256(key_entry.get().encode()).digest()
        with open(selected_file_path, "rb") as f: r = f.read()
        cipher = AES.new(k, AES.MODE_GCM, nonce=r[:16])
        plain = zlib.decompress(cipher.decrypt_and_verify(r[32:], r[16:32]))
        out = selected_file_path[:-7] if selected_file_path.endswith(".anigma") else selected_file_path + ".dec"
        with open(out, "wb") as f: f.write(plain)
        root.after(0, lambda: file_success_ui(out))
    except: root.after(0, lambda: messagebox.showerror("ERROR", "خطا! کلید اشتباه است."))

def file_success_ui(p): messagebox.showinfo("OK", f"عملیات موفقیت‌آمیز:\n{os.path.basename(p)}")

def copy_output():
    t = result_entry.get("1.0", tk.END).strip()
    if t: root.clipboard_clear(); root.clipboard_append(t)

def copy_key():
    k = key_entry.get().strip()
    if k: root.clipboard_clear(); root.clipboard_append(k)

def paste_input():
    try: text_entry.delete("1.0", tk.END); text_entry.insert("1.0", root.clipboard_get())
    except: pass

def toggle_password_visibility(): key_entry.config(show="" if show_key_var.get() else "*")
def generate_random_key():
    key_entry.delete(0, tk.END); key_entry.insert(0, "".join(random.choice(string.ascii_letters+string.digits) for _ in range(12))); check_key_strength()

def check_key_strength(e=None):
    k = key_entry.get()
    if not k: strength_label.config(text=LANGUAGES[current_lang]["key_empty"], fg="gray")
    elif len(k) < 6: strength_label.config(text=LANGUAGES[current_lang]["key_weak"], fg="red")
    else: strength_label.config(text=LANGUAGES[current_lang]["key_military"], fg="green")

def encode_message():
    txt, k = text_entry.get("1.0", tk.END).strip(), key_entry.get().strip()
    if not txt or not k: return
    try:
        cipher = AES.new(hashlib.sha256(k.encode()).digest(), AES.MODE_GCM)
        ctx, tag = cipher.encrypt_and_digest(txt.encode('utf-8'))
        result_entry.delete("1.0", tk.END); result_entry.insert("1.0", base64.urlsafe_b64encode(cipher.nonce + tag + ctx).decode('utf-8'))
    except Exception as e: messagebox.showerror("ERROR", str(e))

def decode_message():
    ctx, k = text_entry.get("1.0", tk.END).strip(), key_entry.get().strip()
    if not ctx or not k: return
    try:
        r = base64.urlsafe_b64decode(ctx.encode('utf-8'))
        cipher = AES.new(hashlib.sha256(k.encode()).digest(), AES.MODE_GCM, nonce=r[:16])
        result_entry.delete("1.0", tk.END); result_entry.insert("1.0", cipher.decrypt_and_verify(r[32:], r[16:32]).decode('utf-8'))
    except: messagebox.showerror("ERROR", "خطا!")

def clear_all(): text_entry.delete("1.0", tk.END); key_entry.delete(0, tk.END); result_entry.delete("1.0", tk.END)

load_config()
root = TkinterDnD.Tk()
root.geometry("540x630")
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
btn_copy_key = tk.Button(key_opt_frame, text="Copy", command=copy_key)
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
btn_toggle_log.pack(side="left")
log_box = tk.Text(root, height=2, width=58, bd=1, relief="solid", state="disabled")
log_box.pack(padx=15, pady=2)
status_label = tk.Label(root)
status_label.pack(side="bottom", pady=2)

menu = tk.Menu(root, tearoff=0)
menu.add_command(label=f"Version: {CURRENT_VERSION}", state="disabled")
menu.add_command(label=LANGUAGES[current_lang]["menu_help"], command=open_help)
menu.add_command(label=LANGUAGES[current_lang]["menu_update"], command=check_for_updates)
theme_menu = tk.Menu(menu, tearoff=0)
theme_menu.add_command(label="Night", command=lambda: apply_theme("night"))
theme_menu.add_command(label="Hacker", command=lambda: apply_theme("hacker"))
theme_menu.add_command(label="Light", command=lambda: apply_theme("light"))
menu.add_cascade(label="Theme", menu=theme_menu)
menu_btn.config(command=show_menu)

change_language(current_lang)
root.mainloop()
