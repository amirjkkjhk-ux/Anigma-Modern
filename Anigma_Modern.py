import tkinter as tk
from tkinter import messagebox, ttk, filedialog
# وارد کردن ابزار کشیدن و رها کردن فایل
from tkinterdnd2 import TkinterDnD, DND_FILES 
import base64
import hashlib
import random
import string
import os
import zlib
import threading
import json
from datetime import datetime
from Crypto.Cipher import AES 

CONFIG_FILE = "config.json"

LANGUAGES = {
    "fa": {
        "title": "آنیگما مدرن v11.0 (نسخه پیشرفته)",
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
        "menu_help": "راهنمای کامل استفاده",
        "processing": "وضعیت: در حال پردازش فایل... لطفاً صبر کنید [WAIT]"
    },
    "en": {
        "title": "ANIGMA MODERN v11.0",
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
        "menu_help": "Full User Guide / Help",
        "processing": "STATUS: Processing file... Please wait [WAIT]"
    }
}

current_lang = "fa"
selected_file_path = ""
logs_enabled = True

def load_config():
    global current_lang, logs_enabled
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r") as f:
                config = json.load(f)
                if config.get("language") in LANGUAGES:
                    current_lang = config["language"]
                if "logs_enabled" in config:
                    logs_enabled = config["logs_enabled"]
        except:
            current_lang = "fa"
            logs_enabled = True

def save_config_file():
    try:
        with open(CONFIG_FILE, "w") as f:
            json.dump({"language": current_lang, "logs_enabled": logs_enabled}, f)
    except:
        pass

def add_log(message):
    if not logs_enabled:
        return
    now = datetime.now().strftime("%Y-%b-%d %H:%M:%S")
    log_box.config(state="normal")
    log_box.insert(tk.END, f"[{now}] ", "ltr_log")
    log_box.insert(tk.END, f"{message}\n", "rtl_log" if current_lang == "fa" else "ltr_log")
    log_box.see(tk.END)
    log_box.config(state="disabled")

def toggle_logs():
    global logs_enabled
    logs_enabled = not logs_enabled
    save_config_file()
    update_log_button_ui()
    if logs_enabled:
        add_log("System logs enabled." if current_lang == "en" else "ثبت تاریخچه سیستم فعال شد.")

def update_log_button_ui():
    if logs_enabled:
        btn_toggle_log.config(text=LANGUAGES[current_lang]["log_active"], bg="#2ed573")
    else:
        btn_toggle_log.config(text=LANGUAGES[current_lang]["log_inactive"], bg="#ff4757")

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
    
    # اصلاح بخش تغییر منو برای جلوگیری از خطای ویندوز
    try:
        menu.entryconfigure("راهنمای کامل استفاده", label=LANGUAGES[lang]["menu_help"])
        menu.entryconfigure("Full User Guide / Help", label=LANGUAGES[lang]["menu_help"])
    except:
        pass
        
    update_file_label()
    check_key_strength()

def show_menu():
    menu.post(menu_btn.winfo_rootx(), menu_btn.winfo_rooty() + menu_btn.winfo_height())

def open_help():
    help_window = tk.Toplevel(root)
    help_window.title("ANIGMA MODERN - SYSTEM GUIDE")
    help_window.geometry("520x540")
    help_window.configure(bg="#0d1726")
    help_window.resizable(False, False)
    
    text_widget = tk.Text(help_window, bg="#0d1726", fg="#ffffff", font=("Segoe UI", 10), bd=0, padx=20, pady=20, wrap="word")
    text_widget.tag_configure("fa_style", justify="right", spacing1=5, spacing2=2)
    text_widget.tag_configure("en_style", justify="left", spacing1=5, spacing2=2)
    text_widget.tag_configure("title_style", font=("Segoe UI", 12, "bold"), foreground="#00ffcc", justify="center")
    
    if current_lang == "fa":
        text_widget.insert(tk.END, "--- راهنمای سیستم جدید آنیگما مدرن ---\n\n", "title_style")
        text_widget.insert(tk.END, "این نسخه مجهز به قابلیت Drag & Drop برای فایل‌هاست:\n\n", "fa_style")
        text_widget.insert(tk.END, "• کادر قفل‌گذاری فایل:\n", "fa_style")
        text_widget.insert(tk.END, "علاوه بر دکمه انتخاب فایل، می‌توانید فایل خود را مستقیماً با ماوس به داخل کادر خاکستری بکشید و رها کنید (Drag & Drop) تا به صورت خودکار شناسایی شود.\n", "fa_style")
    else:
        text_widget.insert(tk.END, "--- ANIGMA MODERN SYSTEM GUIDE ---\n\n", "title_style")
        text_widget.insert(tk.END, "This version supports Drag & Drop for easy file handling:\n\n", "en_style")
        text_widget.insert(tk.END, "- Drag & Drop Feature:\n", "en_style")
        text_widget.insert(tk.END, "Simply drag any file from your computer and drop it inside the designated file box to select it instantly.\n", "en_style")
        
    text_widget.config(state="disabled")
    text_widget.pack(fill="both", expand=True)

def drop_inside_file_zone(event):
    global selected_file_path
    file_path = event.data
    if file_path.startswith('{') and file_path.endswith('}'):
        file_path = file_path[1:-1]
    
    if os.path.exists(file_path):
        selected_file_path = file_path
        update_file_label()
        add_log(f"Dropped file: {os.path.basename(file_path)}" if current_lang == "en" else f"فایل رها شد: {os.path.basename(file_path)}")

def select_file():
    global selected_file_path
    file_path = filedialog.askopenfilename()
    if file_path:
        selected_file_path = file_path
        update_file_label()
        add_log(f"Selected file: {os.path.basename(file_path)}" if current_lang == "en" else f"فایل انتخاب شد: {os.path.basename(file_path)}")

def update_file_label():
    if selected_file_path:
        file_name = os.path.basename(selected_file_path)
        lbl_file_status.config(text=file_name, fg="#00ffcc")
    else:
        lbl_file_status.config(text="فایلی انتخاب نشده یا اینجا رها کنید" if current_lang == "fa" else "No file selected / Drop here", fg="#57606f")

def update_progress(current, total):
    percentage = int((current / total) * 100)
    progress_bar["value"] = percentage
    root.update_idletasks()

def start_file_thread(action):
    key = key_entry.get().strip()
    if not selected_file_path or not key:
        messagebox.showwarning("WARNING", LANGUAGES[current_lang]["warning_no_file"])
        return
    status_label.config(text=LANGUAGES[current_lang]["processing"], fg="#ffa500")
    progress_bar["value"] = 0
    root.update_idletasks()
    if action == "encrypt":
        add_log("Starting file encryption process..." if current_lang == "en" else "شروع فرآیند قفل‌گذاری فایل...")
        t = threading.Thread(target=process_encrypt_file, args=(key,))
    else:
        add_log("Starting file decryption process..." if current_lang == "en" else "شروع فرآیند رمزگشایی فایل...")
        t = threading.Thread(target=process_decrypt_file, args=(key,))
    t.start()

def process_encrypt_file(key):
    try:
        hashed_key = hashlib.sha256(key.encode()).digest()
        with open(selected_file_path, "rb") as f:
            file_data = f.read()
            
        root.after(0, lambda: update_progress(30, 100))
        compressed_data = zlib.compress(file_data)
        
        root.after(0, lambda: update_progress(60, 100))
        cipher = AES.new(hashed_key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(compressed_data)
        
        output_path = selected_file_path + ".anigma"
        with open(output_path, "wb") as f:
            f.write(cipher.nonce + tag + ciphertext)
            
        root.after(0, lambda: update_progress(100, 100))
        root.after(0, lambda: file_success_ui(output_path, "encrypt"))
    except Exception as e:
        root.after(0, lambda: update_progress(0, 100))
        root.after(0, lambda: messagebox.showerror("ERROR", str(e)))

def process_decrypt_file(key):
    try:
        hashed_key = hashlib.sha256(key.encode()).digest()
        with open(selected_file_path, "rb") as f:
            raw_data = f.read()
            
        root.after(0, lambda: update_progress(30, 100))
        nonce = raw_data[:16]
        tag = raw_data[16:32]
        ciphertext = raw_data[32:]
        
        root.after(0, lambda: update_progress(60, 100))
        cipher = AES.new(hashed_key, AES.MODE_GCM, nonce=nonce)
        decrypted_compressed = cipher.decrypt_and_verify(ciphertext, tag)
        decrypted_data = zlib.decompress(decrypted_compressed)
        
        output_path = selected_file_path[:-7] if selected_file_path.endswith(".anigma") else selected_file_path + ".decrypted"
        with open(output_path, "wb") as f:
            f.write(decrypted_data)
            
        root.after(0, lambda: update_progress(100, 100))
        root.after(0, lambda: file_success_ui(output_path, "decrypt"))
    except:
        root.after(0, lambda: update_progress(0, 100))
        root.after(0, lambda: file_error_ui())

def file_success_ui(path, mode):
    name = os.path.basename(path)
    if mode == "encrypt":
        status_label.config(text=LANGUAGES[current_lang]["status_file_enc"], fg="#ff0055")
        add_log(f"File encrypted -> {name}" if current_lang == "en" else f"فایل با موفقیت قفل شد -> {name}")
        messagebox.showinfo("SUCCESS", f"فایل با موفقیت فشرده و رمزگذاری شد:\n{name}")
    else:
        status_label.config(text=LANGUAGES[current_lang]["status_file_dec"], fg="#2ed573")
        add_log(f"File decrypted -> {name}" if current_lang == "en" else f"فایل با موفقیت باز شد -> {name}")
        messagebox.showinfo("SUCCESS", f"فایل با موفقیت رمزگشایی و بازسازی شد:\n{name}")

def file_error_ui():
    status_label.config(text=LANGUAGES[current_lang]["status_online"], fg="#8a9fc4")
    add_log("File processing failed." if current_lang == "en" else "خطا در پردازش فایل.")
    messagebox.showerror("ERROR", LANGUAGES[current_lang]["error_decrypt"])

def copy_output():
    text = result_entry.get("1.0", tk.END).strip()
    if text:
        root.clipboard_clear()
        root.clipboard_append(text)
        status_label.config(text=LANGUAGES[current_lang]["status_copied"], fg="#00ffcc")
    else:
        status_label.config(text=LANGUAGES[current_lang]["status_no_copy"], fg="#ff0055")

def copy_key():
    key = key_entry.get().strip()
    if key:
        root.clipboard_clear()
        root.clipboard_append(key)
        status_label.config(text=LANGUAGES[current_lang]["status_key_copied"], fg="#00ffcc")
    else:
        status_label.config(text=LANGUAGES[current_lang]["status_no_copy"], fg="#ff0055")

def paste_input():
    try:
        text_to_paste = root.clipboard_get()
        text_entry.delete("1.0", tk.END)
        text_entry.insert("1.0", text_to_paste)
        status_label.config(text=LANGUAGES[current_lang]["status_pasted"], fg="#00ffcc")
    except:
        status_label.config(text=LANGUAGES[current_lang]["status_paste_failed"], fg="#ff0055")

def toggle_password_visibility():
    if show_key_var.get():
        key_entry.config(show="")
    else:
        key_entry.config(show="*")

def generate_random_key():
    chars = string.ascii_letters + string.digits + "@#$"
    random_key = "".join(random.choice(chars) for _ in range(12))
    key_entry.delete(0, tk.END)
    key_entry.insert(0, random_key)
    check_key_strength()

def check_key_strength(event=None):
    key = key_entry.get()
    has_upper = any(c.isupper() for c in key)
    has_lower = any(c.islower() for c in key)
    has_digit = any(c.isdigit() for c in key)
    has_spec = any(c in "@#$%^&*()_+-=" for c in key)
    
    if len(key) == 0:
        strength_label.config(text=LANGUAGES[current_lang]["key_empty"], fg="#57606f")
    elif len(key) < 6:
        strength_label.config(text=LANGUAGES[current_lang]["key_weak"], fg="#ff4757")
    elif len(key) >= 10 and has_upper and has_lower and has_digit and has_spec:
        strength_label.config(text=LANGUAGES[current_lang]["key_military"], fg="#2ed573")
    elif len(key) >= 8 and (has_upper or has_lower) and has_digit:
        strength_label.config(text=LANGUAGES[current_lang]["key_strong"], fg="#00ffcc")
    else:
        strength_label.config(text=LANGUAGES[current_lang]["key_good"], fg="#ffa500")

def encode_message():
    clear_text = text_entry.get("1.0", tk.END)
    if clear_text.endswith('\n'):
        clear_text = clear_text[:-1]
    key = key_entry.get().strip()
    if not clear_text or not key:
        messagebox.showwarning("WARNING", LANGUAGES[current_lang]["warning_empty"])
        return
    try:
        hashed_key = hashlib.sha256(key.encode()).digest()
        cipher = AES.new(hashed_key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(clear_text.encode('utf-8'))
        combined = cipher.nonce + tag + ciphertext
        final_encoded = base64.urlsafe_b64encode(combined).decode('utf-8')
        result_entry.delete("1.0", tk.END)
        result_entry.insert("1.0", final_encoded)
        status_label.config(text=LANGUAGES[current_lang]["status_encrypted"], fg="#ff0055")
    except Exception as e:
        messagebox.showerror("ERROR", str(e))

def decode_message():
    cipher_text = text_entry.get("1.0", tk.END).strip()
    key = key_entry.get().strip()
    if not cipher_text or not key:
        messagebox.showwarning("WARNING", LANGUAGES[current_lang]["warning_empty"])
        return
    try:
        hashed_key = hashlib.sha256(key.encode()).digest()
        raw_data = base64.urlsafe_b64decode(cipher_text.encode('utf-8'))
        nonce = raw_data[:16]
        tag = raw_data[16:32]
        ciphertext = raw_data[32:]
        cipher = AES.new(hashed_key, AES.MODE_GCM, nonce=nonce)
        decrypted_bytes = cipher.decrypt_and_verify(ciphertext, tag)
        final_decoded = decrypted_bytes.decode('utf-8')
        result_entry.delete("1.0", tk.END)
        result_entry.insert("1.0", final_decoded)
        status_label.config(text=LANGUAGES[current_lang]["status_decrypted"], fg="#2ed573")
    except:
        messagebox.showerror("ERROR", LANGUAGES[current_lang]["error_decrypt"])

def clear_all():
    global selected_file_path
    text_entry.delete("1.0", tk.END)
    key_entry.delete(0, tk.END)
    result_entry.delete("1.0", tk.END)
    selected_file_path = ""
    progress_bar["value"] = 0
    update_file_label()
    check_key_strength()
    status_label.config(text=LANGUAGES[current_lang]["status_cleared"], fg="#8a9fc4")

load_config()

# روت اصلی با موتور کشیدن و رها کردن فایل
root = TkinterDnD.Tk()
root.title(LANGUAGES[current_lang]["title"])
root.geometry("540x630")
root.configure(bg="#050a12")
root.resizable(False, False)

style = ttk.Style()
style.theme_use('default')
style.configure("TNotebook", background="#050a12", borderwidth=0)
style.configure("TNotebook.Tab", background="#0d1726", foreground="#8a9fc4", font=("Segoe UI", 9, "bold"), padding=[15, 5])
style.map("TNotebook.Tab", background=[("selected", "#341f97")], foreground=[("selected", "#ffffff")])
style.configure("Horizontal.TProgressbar", thickness=7, troughcolor="#0d1726", background="#00ffcc", bordercolor="#050a12")

# Top Bar
top_bar = tk.Frame(root, bg="#050a12")
top_bar.pack(fill="x", padx=10, pady=5)

menu_btn = tk.Button(top_bar, text=" ☰ ", font=("Segoe UI", 11, "bold"), bg="#0d1726", fg="#00ffcc", bd=0, cursor="hand2", command=show_menu)
menu_btn.pack(side="left")

protocol_label = tk.Label(top_bar, text=LANGUAGES[current_lang]["protocol"], font=("Segoe UI", 9, "bold"), bg="#050a12", fg="#00ffcc")
protocol_label.pack(side="left", expand=True)

menu = tk.Menu(root, tearoff=0, bg="#0d1726", fg="#ffffff", activebackground="#341f97", activeforeground="white")
menu.add_command(label="Developer: AmirMahdi Basavand", state="disabled")
menu.add_command(label="Version: 11.0 (Fix Complete)", state="disabled")
menu.add_separator()
menu.add_command(label=LANGUAGES[current_lang]["menu_help"], command=open_help)
menu.add_separator()
lang_menu = tk.Menu(menu, tearoff=0, bg="#0d1726", fg="#ffffff", activebackground="#341f97")
lang_menu.add_command(label="فارسی (FA)", command=lambda: change_language("fa"))
lang_menu.add_command(label="English (EN)", command=lambda: change_language("en"))
menu.add_cascade(label="Language / زبان", menu=lang_menu)

# GLOBAL KEY ZONE
global_key_frame = tk.Frame(root, bg="#0b121f", bd=1, relief="solid")
global_key_frame.pack(fill="x", padx=15, pady=5)

key_title_frame = tk.Frame(global_key_frame, bg="#0b121f")
key_title_frame.pack(fill="x", padx=10, pady=2)
lbl_key = tk.Label(key_title_frame, text=LANGUAGES[current_lang]["key_label"], bg="#0b121f", fg="#8a9fc4", font=("Segoe UI", 9, "bold"))
lbl_key.pack(side="left")
strength_label = tk.Label(key_title_frame, text=LANGUAGES[current_lang]["key_empty"], bg="#0b121f", fg="#57606f", font=("Segoe UI", 9, "bold"))
strength_label.pack(side="right")

key_entry = tk.Entry(global_key_frame, font=("Arial", 11, "bold"), show="*", bg="#0d1726", fg="#ff0055", insertbackground="#ff0055", bd=1, relief="solid")
key_entry.pack(fill="x", padx=10, pady=2)
key_entry.bind("<KeyRelease>", check_key_strength)

key_opt_frame = tk.Frame(global_key_frame, bg="#0b121f")
key_opt_frame.pack(fill="x", padx=10, pady=4)

show_key_var = tk.BooleanVar()
show_key_btn = tk.Checkbutton(key_opt_frame, text=LANGUAGES[current_lang]["show_key"], variable=show_key_var, command=toggle_password_visibility, bg="#0b121f", fg="#8a9fc4", selectcolor="#0b121f", activebackground="#0b121f")
show_key_btn.pack(side="left")

btn_copy_key = tk.Button(key_opt_frame, text=LANGUAGES[current_lang]["copy_key"], command=copy_key, bg="#4b5563", fg="white", font=("Segoe UI", 8), bd=0, padx=6, cursor="hand2")
btn_copy_key.pack(side="right", padx=2)

btn_rand_key = tk.Button(key_opt_frame, text=LANGUAGES[current_lang]["rand_key"], command=generate_random_key, bg="#78e08f", fg="#050a12", font=("Segoe UI", 8, "bold"), bd=0, padx=6, cursor="hand2")
btn_rand_key.pack(side="right", padx=2)

# Notebook
notebook = ttk.Notebook(root)
notebook.pack(fill="both", expand=True, padx=15, pady=5)

tab_text_frame = tk.Frame(notebook, bg="#050a12")
tab_file_frame = tk.Frame(notebook, bg="#050a12")

notebook.add(tab_text_frame, text=LANGUAGES[current_lang]["tab_text"])
notebook.add(tab_file_frame, text=LANGUAGES[current_lang]["tab_file"])

# Tab 1
lbl_input = tk.Label(tab_text_frame, text=LANGUAGES[current_lang]["input_label"], bg="#050a12", fg="#8a9fc4", font=("Segoe UI", 9))
lbl_input.pack(anchor="w", padx=10, pady=2)
text_entry = tk.Text(tab_text_frame, height=3, width=58, font=("Segoe UI", 10), bg="#0d1726", fg="#00ffcc", bd=1, relief="solid")
text_entry.pack()

btn_paste = tk.Button(tab_text_frame, text=LANGUAGES[current_lang]["paste_btn"], command=paste_input, bg="#341f97", fg="white", font=("Segoe UI", 9, "bold"), bd=0, pady=3, cursor="hand2")
btn_paste.pack(fill="x", padx=10, pady=4)

btn_frame = tk.Frame(tab_text_frame, bg="#050a12")
btn_frame.pack(pady=4)
encrypt_btn = tk.Button(btn_frame, text=LANGUAGES[current_lang]["encrypt"], command=encode_message, bg="#ff0055", fg="white", font=("Segoe UI", 9, "bold"), padx=15, pady=4, bd=0, cursor="hand2")
encrypt_btn.pack(side="left", padx=5)
decrypt_btn = tk.Button(btn_frame, text=LANGUAGES[current_lang]["decrypt"], command=decode_message, bg="#00ffcc", fg="#050a12", font=("Segoe UI", 9, "bold"), padx=15, pady=4, bd=0, cursor="hand2")
decrypt_btn.pack(side="left", padx=5)
clear_btn = tk.Button(btn_frame, text=LANGUAGES[current_lang]["clear"], command=clear_all, bg="#57606f", fg="white", font=("Segoe UI", 9, "bold"), padx=10, pady=4, bd=0, cursor="hand2")
clear_btn.pack(side="left", padx=5)

lbl_output = tk.Label(tab_text_frame, text=LANGUAGES[current_lang]["output_label"], bg="#050a12", fg="#8a9fc4", font=("Segoe UI", 9))
lbl_output.pack(anchor="w", padx=10, pady=2)
result_entry = tk.Text(tab_text_frame, height=3, width=58, font=("Segoe UI", 10), bg="#090f1a", fg="#ffffff", bd=1, relief="solid")
result_entry.pack()

btn_copy_output = tk.Button(tab_text_frame, text=LANGUAGES[current_lang]["copy_output"], command=copy_output, bg="#2ed573", fg="white", font=("Segoe UI", 9, "bold"), bd=0, pady=4, cursor="hand2")
btn_copy_output.pack(fill="x", padx=10, pady=4)

# Tab 2
lbl_file = tk.Label(tab_file_frame, text=LANGUAGES[current_lang]["file_section"], bg="#050a12", fg="#8a9fc4", font=("Segoe UI", 9, "bold"))
lbl_file.pack(anchor="w", padx=10, pady=10)

# باکس دریافت فایل
drop_zone_box = tk.LabelFrame(tab_file_frame, text=" DRAG & DROP ZONE ", bg="#0f192a", fg="#8a9fc4", font=("Consolas", 9, "bold"), bd=1, relief="solid")
drop_zone_box.pack(fill="x", padx=10, pady=5, ipady=15)

drop_zone_box.drop_target_register(DND_FILES)
drop_zone_box.dnd_bind('<<Drop>>', drop_inside_file_zone)

btn_select_file = tk.Button(drop_zone_box, text=LANGUAGES[current_lang]["select_file_btn"], command=select_file, bg="#1e2736", fg="#00ffcc", font=("Segoe UI", 9), bd=1, relief="solid", cursor="hand2", padx=10, pady=4)
btn_select_file.pack(pady=5)

lbl_file_status = tk.Label(drop_zone_box, text="فایلی انتخاب نشده یا اینجا رها کنید", bg="#0f192a", fg="#57606f", font=("Segoe UI", 9, "italic"))
lbl_file_status.pack(pady=2)

file_btn_frame = tk.Frame(tab_file_frame, bg="#050a12")
file_btn_frame.pack(pady=10)
btn_enc_file = tk.Button(file_btn_frame, text=LANGUAGES[current_lang]["enc_file_btn"], command=lambda: start_file_thread("encrypt"), bg="#d32f2f", fg="white", font=("Segoe UI", 9, "bold"), padx=25, pady=6, bd=0, cursor="hand2")
btn_enc_file.pack(side="left", padx=10)
btn_dec_file = tk.Button(file_btn_frame, text=LANGUAGES[current_lang]["dec_file_btn"], command=lambda: start_file_thread("decrypt"), bg="#388e3c", fg="white", font=("Segoe UI", 9, "bold"), padx=25, pady=6, bd=0, cursor="hand2")
btn_dec_file.pack(side="left", padx=10)

progress_bar = ttk.Progressbar(tab_file_frame, orient="horizontal", length=430, mode="determinate")
progress_bar.pack(pady=5)

# Footer Logs
separator = ttk.Separator(root, orient='horizontal')
separator.pack(fill='x', padx=15, pady=2)

log_title_frame = tk.Frame(root, bg="#050a12")
log_title_frame.pack(fill="x", padx=35, pady=2)
lbl_log = tk.Label(log_title_frame, text=LANGUAGES[current_lang]["log_section"], bg="#050a12", fg="#8a9fc4", font=("Segoe UI", 9, "bold"))
lbl_log.pack(side="right")
btn_toggle_log = tk.Button(log_title_frame, text=LANGUAGES[current_lang]["log_active"], command=toggle_logs, font=("Segoe UI", 8, "bold"), fg="white", bd=0, padx=6, cursor="hand2")
btn_toggle_log.pack(side="left")

log_box = tk.Text(root, height=2, width=58, font=("Consolas", 9), bg="#02060d", fg="#8a9fc4", bd=1, relief="solid", state="disabled")
log_box.tag_configure("rtl_log", justify="right")
log_box.tag_configure("ltr_log", justify="left")
log_box.pack(padx=15, pady=2)

status_label = tk.Label(root, text=LANGUAGES[current_lang]["status_online"], font=("Segoe UI", 8), bg="#050a12", fg="#8a9fc4")
status_label.pack(side="bottom", pady=2)

change_language(current_lang)
root.mainloop()
