# --- IMPORTS ---
import os
import base64
import customtkinter as ctk  # Custom version of Tkinter for modern UI
from tkinter import filedialog  # For file selection dialogs
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC  # Key derivation
from cryptography.hazmat.primitives import hashes  # Hashing algorithms
from cryptography.fernet import Fernet  # Symmetric encryption (AES under the hood)
from cryptography.hazmat.backends import default_backend  # Backend for crypto functions

# --- ENCRYPTION UTILITIES ---

# 🔑 Derives a 256-bit key from a password and a salt using PBKDF2
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),  # Use SHA-256 for hashing
        length=32,                  # 256-bit key
        salt=salt,                  # Random salt to prevent dictionary attacks
        iterations=390000,          # Iteration count for increased security
        backend=default_backend()   # Use default backend
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))  # Return encoded key

# 🔐 Encrypts a file with a password
def encrypt_file(filepath, password):
    salt = os.urandom(16)  # Generate a 16-byte salt
    key = derive_key(password, salt)  # Derive encryption key
    fernet = Fernet(key)  # Initialize Fernet with the derived key

    with open(filepath, 'rb') as f:
        data = f.read()  # Read the file contents

    encrypted = fernet.encrypt(data)  # Encrypt data
    output_path = filepath + '.enc'  # Output file path with .enc extension

    with open(output_path, 'wb') as f:
        f.write(salt + encrypted)  # Write salt followed by encrypted data

    return output_path  # Return path to encrypted file

# 🔓 Decrypts a file with a password
def decrypt_file(filepath, password):
    with open(filepath, 'rb') as f:
        content = f.read()  # Read encrypted file contents

    salt = content[:16]  # Extract salt from the beginning
    encrypted = content[16:]  # Extract encrypted data
    key = derive_key(password, salt)  # Re-derive key from salt and password
    fernet = Fernet(key)

    decrypted = fernet.decrypt(encrypted)  # Decrypt the data
    output_path = filepath.replace('.enc', '.dec')  # Output file path

    with open(output_path, 'wb') as f:
        f.write(decrypted)  # Save decrypted content

    return output_path  # Return path to decrypted file

# --- GUI CALLBACK FUNCTIONS ---

# 📂 Opens a file dialog to select a file
def browse_file():
    path = filedialog.askopenfilename()  # Open file browser
    file_entry.delete(0, ctk.END)  # Clear entry
    file_entry.insert(0, path)  # Insert selected path

# 🔒 Handles encryption logic triggered by Encrypt button
def handle_encrypt():
    path = file_entry.get()
    pwd = password_entry.get()
    if not path or not pwd:
        status_label.configure(text="Please select a file and enter password.", text_color="#f5a623")
        return
    try:
        out = encrypt_file(path, pwd)
        status_label.configure(text=f"✅ Encrypted to:\n{out}", text_color="#2ecc71")
    except Exception as e:
        status_label.configure(text=f"❌ Encryption failed:\n{str(e)}", text_color="#e74c3c")

# 🔓 Handles decryption logic triggered by Decrypt button
def handle_decrypt():
    path = file_entry.get()
    pwd = password_entry.get()
    if not path or not pwd:
        status_label.configure(text="Please select a file and enter password.", text_color="#f5a623")
        return
    try:
        out = decrypt_file(path, pwd)
        status_label.configure(text=f"✅ Decrypted to:\n{out}", text_color="#3498db")
    except Exception as e:
        status_label.configure(text=f"❌ Decryption failed:\n{str(e)}", text_color="#e74c3c")

# --- GUI SETUP ---

# 🌑 Set dark theme appearance and color scheme
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")

# 🖥️ Initialize main application window
app = ctk.CTk()
app.title("🔐 Advanced File Encryptor")
app.geometry("520x400")
app.resizable(False, False)

# 🏷️ Header/title label
title = ctk.CTkLabel(app, text="🔐 Advanced File Encryptor", font=("Helvetica", 24, "bold"), text_color="#1abc9c")
title.pack(pady=(20, 10))

# 📁 File entry and browse button
file_entry = ctk.CTkEntry(app, placeholder_text="Choose file...", width=400, height=40, border_width=2, corner_radius=10)
file_entry.pack(pady=10)

browse_button = ctk.CTkButton(
    app, text="📂 Browse", width=120, command=browse_file,
    fg_color="#f39c12", hover_color="#d35400"
)
browse_button.pack(pady=(0, 20))

# 🔑 Password entry
password_entry = ctk.CTkEntry(app, placeholder_text="Enter password", show="*", width=400, height=40, border_width=2, corner_radius=10)
password_entry.pack(pady=10)

# 🔘 Encrypt and Decrypt buttons
encrypt_btn = ctk.CTkButton(app, text="🔒 Encrypt", command=handle_encrypt, width=180, fg_color="#2ecc71", hover_color="#27ae60")
decrypt_btn = ctk.CTkButton(app, text="🔓 Decrypt", command=handle_decrypt, width=180, fg_color="#3498db", hover_color="#2980b9")
encrypt_btn.pack(pady=8)
decrypt_btn.pack(pady=8)

# 📝 Status label for feedback
status_label = ctk.CTkLabel(app, text="", font=("Helvetica", 13), wraplength=400, justify="center")
status_label.pack(pady=20)

# 🚀 Run the GUI application
app.mainloop()
