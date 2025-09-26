# 🔒 File Encryption Tool

A simple Python-based desktop application to **encrypt and decrypt files** securely using AES encryption. The tool provides a user-friendly interface built with Tkinter and ensures your sensitive files are protected with a password.

---

## Features

- **Encrypt Files:** Protect any file by encrypting it with a password.
- **Decrypt Files:** Safely decrypt `.enc` files using the correct password.
- **Secure Key Derivation:** Uses PBKDF2 to generate strong encryption keys from passwords.
- **AES Encryption:** Implements AES (CBC mode) with random salt and initialization vector (IV) for strong security.
- **File Verification:** Adds a verification token to ensure decryption only succeeds with the correct password.
- **User-friendly Interface:** Built with Tkinter for easy file selection and password input.
- **Logs and Status:** Shows progress and messages in a scrollable status box.

---

## Demo

Files included in the repository:

- `Demo.mp4` – A demo video showcasing the tool.
- `Demo_file.pdf` – Sample file for encryption.
- `Demo_file.pdf.enc` – Encrypted version of the sample file.
- `Demo_file_decrypted.pdf` – Decrypted version to verify correctness.

---

## Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/Roshni7865/File_Encryption_Decryption_Tool.git
   cd File_Encryption_Decryption_Tool
   ```

2. Install the required Python packages:

   ```bash
   pip install pycryptodome
   ```

3. Run the application:

   ```bash
   python file.py
   ```

## Usage

1. Launch the application.

2. Select File – Browse and select the file you want to encrypt or decrypt.

3. Password – Enter a password for encryption or the password used during encryption for decryption.

4. Confirm Password – Enter the password again for verification (only for encryption).

5. Click Encrypt File or Decrypt File.

6. Check the status box for messages and notifications.

⚠️ Important: Remember your password. It cannot be recovered if lost!
