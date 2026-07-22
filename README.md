<div align="center">
  <h1>🚀 DA-Register</h1>
  <p><b>The Ultimate, Database-Free DirectAdmin Registration Portal</b></p>
  <p>
    <i>Developed by Andy Goldau | © 2026 PanelLayer (Subdomain LTD) & GoMaKe UG</i>
  </p>
  <p>
    📦 <b>Product Page:</b> <a href="https://da-register.panellayer.com/">da-register.panellayer.com</a> &nbsp;|&nbsp;
    🧪 <b>Live Demo:</b> <a href="https://demo.da-register.panellayer.com/">demo.da-register.panellayer.com</a> &nbsp;|&nbsp;
    🌐 <b>Project:</b> <a href="https://panellayer.com/">panellayer.com</a>
  </p>
</div>

---

**DA-Register** is an incredibly robust, secure, and fully-featured self-service registration portal built specifically for DirectAdmin. Designed from the ground up for maximum security, beautiful UI/UX, and GDPR compliance, it requires **zero database setup** (100% flat-file logic) and handles user creation flawlessly through the native DirectAdmin API.

> **DISCLAIMER:** This software is provided "as is" without any warranty of any kind. DA-Register is an independent software solution and is not affiliated with, endorsed by, or sponsored by JBMC Software (DirectAdmin) or its affiliates.

---

## ✨ Enterprise-Grade Features

### 🛡️ Unrivaled Security & Privacy
- **k-Anonymity Password Checks:** Integrates the *Have I Been Pwned* API directly in the client’s browser using the Web Crypto API. Only the first 5 characters of a SHA-1 hash are transmitted—your plaintext password never leaves your browser.
- **Advanced Rate-Limiting (Token Bucket):** Fully protects the DirectAdmin API against brute-force and DDoS spam attacks using a highly efficient, session-independent Token Bucket algorithm based on cryptographically hashed IPs.
- **No Database Required:** Works strictly with local flat files (JSON/PHP). All sensitive log files (`audit.log.php`, `used_codes.php`) are completely locked down and unreadable from the web, regardless of whether your webserver is Apache, LiteSpeed, or NGINX.
- **Strict Content Security Policy (CSP):** Ships with hardened HTTP response headers (CSP, HSTS, X-Frame-Options) out of the box, mitigating XSS and iframe-injection attacks.

### 🌐 Internationalization & UX
- **20+ Supported Languages:** Comes fully translated into 20 languages (English, German, French, Spanish, Russian, Chinese, Thai, and more).
- **Responsive Dark/Light Mode:** Automatically adjusts its premium UI to the system preferences of your users.
- **Live Password Checklist:** A real-time, side-by-side interactive UI element that instantly visually validates password complexity requirements.
- **Fail-open DNS MX Checks:** Automatically verifies the existence of mail servers (MX records) for the email domains entered during registration to prevent bot signups, featuring built-in caching.

### 🤖 Ultimate Anti-Bot Protection
Forget spam. We support natively integrated setups for:
- **hCaptcha**
- **reCAPTCHA (Google)**
- **Cloudflare Turnstile**
- **Altcha** (Proof-of-Work, 100% GDPR compliant)
- **MTCaptcha**

### 🎟️ Exclusive Access Modes
- **Invite-Only Mode:** Optionally lock your registration portal so only users with pre-generated, single-use, or multi-use invitation codes can join your platform.

---

## 🚀 Installation & Setup

1. **Upload & Extract:** Upload the contents to any PHP 8.x web directory.
2. **Configure:** Open `config.php` and enter your:
   - DirectAdmin Host, Port, and API Credentials
   - Package name and default IP
   - Desired Captcha Provider Keys
   - Security toggles (HIBP, Invite-Mode, Audit Logging)
3. **Generate a Salt:** Replace the default `LOG_IP_SALT` in `config.php` with a random 32-character string to ensure IP pseudonymization in your audit logs.
4. **Done:** The system automatically creates and protects the necessary `data/` and `logs/` folders upon the first registration.

## 📄 License & Attribution

This project is licensed under the **MIT License**.

> **Developer:** Andy Goldau  
> **Copyright:** © 2026 DA-Register by PanelLayer, a brand of Subdomain LTD and managed on behalf of GoMaKe UG. All rights reserved.  
> **Product Page:** [https://da-register.panellayer.com/](https://da-register.panellayer.com/)  
> **Live Demo:** [https://demo.da-register.panellayer.com/](https://demo.da-register.panellayer.com/)  
> **Project:** [https://panellayer.com/](https://panellayer.com/)

The above copyright notice, the developer attribution, and the permission notice must be included in all copies or substantial portions of the Software.
