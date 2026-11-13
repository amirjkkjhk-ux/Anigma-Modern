<div align="center">

<img src="dist/icons/icon-192.png" width="96" alt="Anigma" />

# Anigma · آنیگما

**Private, offline-first encryption for messages and files — for everyone, everywhere.**
**رمزنگاری خصوصی و آفلاین پیام‌ها و فایل‌ها — برای همه، در همه‌جا.**

[English](#english) · [فارسی](#فارسی)

</div>

---

<a id="english"></a>
## English

### What is Anigma?
Anigma is a free, open application that lets you encrypt text messages and files with modern public-key cryptography, entirely on your own device. You write or choose something, Anigma turns it into an unreadable package, and only the person you chose can open it. You can send that package over any channel — messenger, email, SMS, USB stick, printed QR code — without trusting the channel.

There is **no account, no sign-up, no server that stores your data, and no analytics**. Your keys are created on your device and never leave it.

### Why it exists
Anigma was built with a humanitarian goal: **to protect the privacy and safety of ordinary people.** Journalists, activists, aid workers, patients, families, students and anyone living under surveillance or censorship should be able to communicate without fear. Privacy is a basic human right, and strong cryptography should be usable by non-experts, in any language, on any device, even with a poor or monitored internet connection. Anigma aims to make that easy: a simple mode for everyday users and an advanced mode for experts.

### Features
- **End-to-end encryption** of messages and files, with a modern, authenticated cipher (AES-GCM) and key exchange (ECDH P-256, optional X25519).
- **Strong password protection** for your identity using memory-hard key derivation (Argon2id).
- **Offline-first:** after installation it works without internet. Nothing is uploaded.
- **Contacts via QR code**, with verification codes so you can confirm you are really talking to the right person.
- **Encrypted groups** with member removal.
- **Encrypted identity backup** that only you can open.
- **Simple & Advanced modes**, full **Persian (فارسی) and English** interface, right-to-left support.
- **Runs everywhere:** Android (APK), Windows (installer), and any modern browser / installable web app (PWA) on phone, tablet and desktop.
- **Signed updates:** the app only accepts update announcements that carry a valid digital signature, so a hacked server cannot push a fake update.

### Download
Get the latest version from the **[Releases](../../releases)** page:

| Platform | File |
|---|---|
| Android | `Anigma.apk` |
| Windows | `Anigma-Setup.exe` |

Verify the SHA-256 checksum shown in the release before installing. On Android you may need to allow “install from this source”. Windows may show a SmartScreen notice because the installer is not yet signed with a paid code-signing certificate — choose *More info → Run anyway* only if the checksum matches.

### Privacy & security notes
- Everything is processed locally. Anigma does not collect personal data.
- The only network request the app makes is a small check for signed update information on GitHub, which — like any web request — reveals your IP address to GitHub.
- The app uses the cryptography built into your platform (Web Crypto API); no cryptographic primitive is implemented by hand.
- **Please be honest with yourself about limits:** Anigma has not been independently audited by a third party yet, and no software can protect a device that is already compromised. Use a long, unique password, keep your device updated, and back up your identity.

### Build from source
This repository builds the Android APK and Windows installer automatically with GitHub Actions (**Actions → Build Anigma (APK + EXE) → Run workflow**). The web app lives in `dist/`; the Android shell uses Capacitor and the Windows shell uses Electron (`native/`, `electron/`).

### Disclaimer
Provided “as is”, without warranty. Use it lawfully and responsibly.

---

<a id="فارسی"></a>
<div dir="rtl">

## فارسی

### آنیگما چیست؟
آنیگما یک برنامهٔ رایگان است که پیام‌های متنی و فایل‌های شما را با رمزنگاری کلید عمومی و مدرن، کاملاً روی دستگاه خودتان رمزگذاری می‌کند. شما متن یا فایل را انتخاب می‌کنید، آنیگما آن را به یک بستهٔ ناخوانا تبدیل می‌کند و فقط کسی که انتخاب کرده‌اید می‌تواند بازش کند. این بسته را از هر مسیری می‌توانید بفرستید — پیام‌رسان، ایمیل، پیامک، فلش یا QR چاپ‌شده — بدون این‌که لازم باشد به آن مسیر اعتماد کنید.

**حساب کاربری، ثبت‌نام، سروری که داده‌های شما را نگه دارد و ابزار ردیابی وجود ندارد.** کلیدهای شما روی دستگاه خودتان ساخته می‌شوند و از آن بیرون نمی‌روند.

### چرا ساخته شد؟
آنیگما با هدفی **بشردوستانه** ساخته شده است: **حفاظت از حریم خصوصی و امنیت مردم عادی.** روزنامه‌نگاران، فعالان، امدادگران، بیماران، خانواده‌ها، دانشجویان و هر کسی که زیر نظارت یا سانسور زندگی می‌کند باید بتواند بدون ترس ارتباط برقرار کند. حریم خصوصی حق اساسی انسان است و رمزنگاری قوی باید برای افراد غیرمتخصص، به هر زبانی، روی هر دستگاهی و حتی با اینترنت ضعیف یا تحت نظارت، قابل استفاده باشد. آنیگما می‌خواهد این کار را ساده کند: حالت ساده برای کاربران روزمره و حالت پیشرفته برای متخصصان.

### امکانات
- **رمزنگاری سرتاسری** پیام‌ها و فایل‌ها با رمزگذاری مدرن و احرازهویت‌شده (AES-GCM) و تبادل کلید (ECDH P-256 و در صورت انتخاب X25519).
- **محافظت قوی از هویت با رمز عبور** با روش مشتق‌سازی کلید حافظه‌سخت (Argon2id).
- **کار آفلاین:** پس از نصب بدون اینترنت کار می‌کند و چیزی آپلود نمی‌شود.
- **افزودن مخاطب با QR** و کد تأیید برای اطمینان از این‌که واقعاً با فرد درست در ارتباطید.
- **گروه‌های رمزگذاری‌شده** همراه با حذف عضو.
- **پشتیبان رمزگذاری‌شدهٔ هویت** که فقط خودتان می‌توانید باز کنید.
- **حالت ساده و پیشرفته**، رابط کامل **فارسی و انگلیسی** و پشتیبانی راست‌به‌چپ.
- **اجرا در همه‌جا:** اندروید (APK)، ویندوز (نصب‌کننده) و هر مرورگر مدرن / وب‌اپ نصب‌شدنی (PWA) روی موبایل، تبلت و کامپیوتر.
- **به‌روزرسانی امضاشده:** برنامه فقط اعلان‌های به‌روزرسانی را می‌پذیرد که امضای دیجیتال معتبر داشته باشند؛ پس سروری که هک شده نمی‌تواند نسخهٔ جعلی تحمیل کند.

### دانلود
آخرین نسخه را از صفحهٔ **[Releases](../../releases)** بگیرید:

| سیستم‌عامل | فایل |
|---|---|
| اندروید | `Anigma.apk` |
| ویندوز | `Anigma-Setup.exe` |

پیش از نصب، مقدار SHA-256 درج‌شده در release را بررسی کنید. در اندروید ممکن است لازم باشد «نصب از این منبع» را مجاز کنید. ویندوز ممکن است هشدار SmartScreen نشان دهد، چون نصب‌کننده هنوز با گواهی تجاریِ امضای کد امضا نشده است؛ فقط اگر مقدار SHA-256 درست بود، *More info ← Run anyway* را بزنید.

### نکات حریم خصوصی و امنیت
- همهٔ پردازش‌ها محلی است و آنیگما داده‌ٔ شخصی جمع‌آوری نمی‌کند.
- تنها درخواست شبکه‌ای برنامه، بررسی کوچکِ اطلاعات امضاشدهٔ به‌روزرسانی در گیت‌هاب است که — مثل هر درخواست وب — آدرس IP شما را به گیت‌هاب نشان می‌دهد.
- برنامه از رمزنگاری داخلی خود پلتفرم (Web Crypto API) استفاده می‌کند و هیچ الگوریتم رمزنگاری‌ای را دستی پیاده نکرده است.
- **صادقانه دربارهٔ محدودیت‌ها:** آنیگما هنوز توسط شخص ثالث مستقل ممیزی نشده و هیچ نرم‌افزاری نمی‌تواند از دستگاهِ از‌قبل‌آلوده محافظت کند. رمز عبور بلند و یکتا بگذارید، دستگاهتان را به‌روز نگه دارید و از هویت خود پشتیبان بگیرید.

### ساخت از روی سورس
این مخزن APK اندروید و نصب‌کنندهٔ ویندوز را به‌صورت خودکار با GitHub Actions می‌سازد (**Actions ← Build Anigma (APK + EXE) ← Run workflow**). برنامهٔ وب در `dist/` است؛ پوستهٔ اندروید با Capacitor و پوستهٔ ویندوز با Electron ساخته می‌شود (`native/` و `electron/`).

### سلب مسئولیت
این برنامه «همان‌گونه که هست» و بدون هیچ ضمانتی ارائه می‌شود. لطفاً قانونی و مسئولانه از آن استفاده کنید.

</div>
