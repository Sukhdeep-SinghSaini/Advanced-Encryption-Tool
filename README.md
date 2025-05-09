# Advanced-Encryption-Tool

*COMPANY*: CODTECH IT SOLUTION

*NAME*: SUKHDEEP SINGH

*INTERN ID*: CT04DK913

*DOMAIN*: CYBER SECURITY & ETHICAL HACKER

*DURATION*: 4 WEEKS

*MENTOR*: NEELA SANTOSH

DESCRIPTION

# 🔐Advanced-Encryption-Tool

A powerful, user-friendly encryption tool built in Python that leverages **AES-256 encryption** to securely encrypt and decrypt files. This application features a **modern dark mode GUI** built with `customtkinter`, making it both functional and visually appealing. With just a few clicks, you can protect sensitive documents using advanced cryptography under a clean, minimal interface.

## 🌟 Features

* **AES-256 Encryption**: Utilizes the Advanced Encryption Standard (AES) with a 256-bit key for strong file security.
* **Password-Based Protection**: Uses PBKDF2 (Password-Based Key Derivation Function 2) to derive secure encryption keys from your password.
* **Salted Key Derivation**: Each file is encrypted with a unique salt for maximum cryptographic strength.
* **Modern GUI**: Clean, responsive interface using `customtkinter` with a sleek dark mode theme.
* **Simple Workflow**: Select your file, enter a password, and click "Encrypt" or "Decrypt". That’s it!
* **Status Feedback**: Real-time color-coded status messages to inform the user about success or failure of actions.

## 🖼️ Interface Preview

* Dark-themed window with vibrant buttons
* Input field for file path with a "Browse" button
* Secure password entry with masking
* One-click "Encrypt" and "Decrypt" buttons
* Output and errors shown in a friendly, centered status label

## 🔧 Technologies Used

* **Python 3.8+**
* `customtkinter` for a modern, themed GUI (built on top of Tkinter)
* `cryptography` library for AES-256 encryption and decryption
* `PBKDF2HMAC` for password-to-key conversion
* `Fernet` for authenticated encryption

## 📅 Installation

Install the required dependencies with pip:

```bash
pip install customtkinter cryptography
```

## ▶️ Usage

1. **Run the script**:

   ```bash
   python aes_gui.py
   ```

2. **Encrypting a File**:

   * Click "📂 Browse" to select the file.
   * Enter a secure password.
   * Click the "🔒 Encrypt" button.
   * A new `.enc` file will be saved in the same directory.

3. **Decrypting a File**:

   * Select a previously encrypted `.enc` file.
   * Enter the same password used to encrypt.
   * Click "🔓 Decrypt" to recover the original file as `.dec`.

## 🔐 Security Details

* AES-256 is implemented using the `Fernet` module backed by a securely derived key.
* Key derivation uses PBKDF2HMAC with SHA-256 and 390,000 iterations.
* Each encryption includes a unique 128-bit salt prepended to the encrypted output.
* Decryption verifies file integrity and password validity; incorrect passwords will not silently produce corrupted files.

## 💡 Why Use This Tool?

In an age of increasing digital threats, securing files locally before transmission or cloud storage is essential. This tool makes encryption accessible to non-programmers by wrapping best-in-class cryptographic algorithms in a beginner-friendly graphical interface. Whether you're securing business documents, personal data, or sensitive intellectual property, this tool gives you full control with zero technical barrier.

## 📁 Output Files

* Encrypted files are saved as `filename.ext.enc`
* Decrypted files are saved as `filename.ext.dec`

## 🧱 Future Enhancements

* Drag-and-drop support
* File integrity check before decryption
* Multi-file batch encryption
* Biometric or 2FA-based key unlocking (optional)
* Platform-specific packaging (.exe, .app)

## 👨‍💻 Author

Made with ❤️ by Sukhdeep Singh

## Output

![Image](https://github.com/user-attachments/assets/a043c07a-a151-4a04-8561-3341dc75d011)

****Encryption****

![Image](https://github.com/user-attachments/assets/e382c3dd-0cff-4ab5-9546-719b8175a54f)

****Decryption****

![Image](https://github.com/user-attachments/assets/4fb64ae1-6984-4a50-936f-3be8eb685160)
