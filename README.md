# SecureFlaskApp 🔐

 **containerized Flask web application** designed with **multiple security mechanisms** to meet the requirements of our cybersecurity project.  
Built to run in **Docker** with best practices for security, authentication, and safe deployment.

---

## 📌 Project Overview
SecureFlaskApp is a demonstration of applying **10+ security mechanisms** in a real-world Flask application inside a container-based environment.  
The project implements **secure coding practices**, **user authentication**, and **defensive configurations** to protect against common web application vulnerabilities.

---

## 🛡 Security Mechanisms Implemented

1. **Containerization** with Docker for isolated environment.
2. **Non-root user** in container to avoid privilege escalation.
3. **Flask session security** with `SECRET_KEY`.
4. **Password hashing** with `werkzeug.security` (PBKDF2).
5. **Environment variable secrets** instead of hardcoding.
6. **Input validation & sanitization** for user forms.
7. **HTTP headers hardening** using Flask extensions.
8. **CSRF protection** for all forms.
9. **Rate limiting** to prevent brute-force attacks.
10. **Secure cookie flags** (`HttpOnly`, `Secure`).
11. **HTTPS-ready configuration** for production.
12. **Disabled server signature** to hide version info.

---

## ⚙️ Installation & Setup

### 1️⃣ Clone the repository
```bash
git clone https://github.com/Mahama-001/SecureFlaskApp.git
cd SecureFlaskApp
