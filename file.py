import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from Crypto.Cipher import AES  # type: ignore
from Crypto.Random import get_random_bytes  # type: ignore
from Crypto.Protocol.KDF import PBKDF2  # type: ignore
import os

class FileEncryptorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("🔒 File Encryption Tool")
        self.root.geometry("700x550")   
        self.root.resizable(True, True)

        # Center window
        self.center_window(700, 550)

        # Variables
        self.file_path = tk.StringVar()
        self.password = tk.StringVar()
        self.confirm_password = tk.StringVar()

        self.setup_ui()

    def center_window(self, width, height):
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        x = (screen_width // 2) - (width // 2)
        y = (screen_height // 2) - (height // 2)
        self.root.geometry(f"{width}x{height}+{x}+{y}")

    def setup_ui(self):
        # Configure root grid
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)

        # Main frame
        main_frame = ttk.Frame(self.root, padding="20")
        main_frame.grid(row=0, column=0, sticky="nsew")

        # Configure columns for centering
        main_frame.columnconfigure(0, weight=1)  # spacer
        main_frame.columnconfigure(1, weight=2)  # main content
        main_frame.columnconfigure(2, weight=1)  # spacer

        # Title
        title_label = ttk.Label(main_frame, text="File Encryption Tool",
                               font=("Arial", 18, "bold"))
        title_label.grid(row=0, column=0, columnspan=3, pady=(0, 20), sticky="n")

        # File selection
        ttk.Label(main_frame, text="Select File:").grid(row=1, column=0, sticky="e", pady=8, padx=5)
        ttk.Entry(main_frame, textvariable=self.file_path, width=40).grid(row=1, column=1, pady=8, sticky="ew")
        ttk.Button(main_frame, text="Browse", command=self.browse_file).grid(row=1, column=2, pady=8, padx=5)

        # Password
        ttk.Label(main_frame, text="Password:").grid(row=2, column=0, sticky="e", pady=8, padx=5)
        ttk.Entry(main_frame, textvariable=self.password, show="*", width=40).grid(row=2, column=1, pady=8, sticky="ew")

        # Confirm Password
        ttk.Label(main_frame, text="Confirm Password:").grid(row=3, column=0, sticky="e", pady=8, padx=5)
        ttk.Entry(main_frame, textvariable=self.confirm_password, show="*", width=40).grid(row=3, column=1, pady=8, sticky="ew")

        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=4, column=0, columnspan=3, pady=15)
        ttk.Button(button_frame, text="Encrypt File", command=self.encrypt_file, width=20).pack(side=tk.LEFT, padx=15)
        ttk.Button(button_frame, text="Decrypt File", command=self.decrypt_file, width=20).pack(side=tk.LEFT, padx=15)

        # Status Box with Scrollbar
        status_frame = ttk.Frame(main_frame)
        status_frame.grid(row=5, column=0, columnspan=3, pady=15, sticky="nsew")
        main_frame.rowconfigure(5, weight=1)

        self.status_text = tk.Text(status_frame, height=12, wrap="word", font=("Consolas", 10))
        self.status_text.pack(side=tk.LEFT, fill="both", expand=True)

        scrollbar = ttk.Scrollbar(status_frame, orient="vertical", command=self.status_text.yview)
        scrollbar.pack(side=tk.RIGHT, fill="y")
        self.status_text.configure(yscrollcommand=scrollbar.set)
        self.status_text.config(state=tk.DISABLED)

    def browse_file(self):
        filename = filedialog.askopenfilename()
        if filename:
            self.file_path.set(filename)
            self.log_message(f"Selected file: {filename}")
            self.password.set("")
            self.confirm_password.set("")

    def log_message(self, message):
        self.status_text.config(state=tk.NORMAL)
        self.status_text.insert(tk.END, message + "\n")
        self.status_text.see(tk.END)
        self.status_text.config(state=tk.DISABLED)

    def derive_key(self, password, salt):
        return PBKDF2(password, salt, 32, count=1000000)

    def encrypt_file(self):
        if not self.file_path.get():
            messagebox.showerror("Error", "Please select a file first!")
            return
        if not self.password.get():
            messagebox.showerror("Error", "Please enter a password!")
            return
        if self.password.get() != self.confirm_password.get():
            messagebox.showerror("Error", "Passwords do not match!")
            return
        try:
            salt = get_random_bytes(16)
            iv = get_random_bytes(16)
            key = self.derive_key(self.password.get(), salt)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            with open(self.file_path.get(), 'rb') as f:
                plaintext = f.read()
            verification_token = b"VALID_FILE_VERIFICATION_TOKEN"
            plaintext = verification_token + plaintext
            padding_length = 16 - (len(plaintext) % 16)
            plaintext += bytes([padding_length] * padding_length)
            ciphertext = cipher.encrypt(plaintext)
            output_file = self.file_path.get() + '.enc'
            with open(output_file, 'wb') as f:
                f.write(salt)
                f.write(iv)
                f.write(ciphertext)
            self.log_message(f"File encrypted successfully: {output_file}")
            self.log_message("⚠️ Remember your password! It cannot be recovered.")
            messagebox.showinfo("Success", f"File encrypted successfully!\nSaved as: {output_file}")
        except Exception as e:
            self.log_message(f"Encryption error: {str(e)}")
            messagebox.showerror("Error", f"Encryption failed: {str(e)}")

    def decrypt_file(self):
        if not self.file_path.get():
            messagebox.showerror("Error", "Please select a file first!")
            return
        if not self.password.get():
            messagebox.showerror("Error", "Please enter a password!")
            return
        if not self.file_path.get().endswith('.enc'):
            messagebox.showerror("Error", "Please select a .enc file for decryption!")
            return
        try:
            with open(self.file_path.get(), 'rb') as f:
                salt = f.read(16)
                iv = f.read(16)
                ciphertext = f.read()
            key = self.derive_key(self.password.get(), salt)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            plaintext = cipher.decrypt(ciphertext)
            padding_length = plaintext[-1]
            plaintext = plaintext[:-padding_length]
            verification_token = b"VALID_FILE_VERIFICATION_TOKEN"
            if not plaintext.startswith(verification_token):
                messagebox.showerror("Error", "Incorrect password! Cannot decrypt.")
                self.log_message("Decryption failed: Incorrect password")
                return
            plaintext = plaintext[len(verification_token):]
            output_file = self.file_path.get()[:-4]
            if os.path.exists(output_file):
                base, ext = os.path.splitext(output_file)
                output_file = base + '_decrypted' + ext
            with open(output_file, 'wb') as f:
                f.write(plaintext)
            self.log_message(f"File decrypted successfully: {output_file}")
            messagebox.showinfo("Success", f"File decrypted successfully!\nSaved as: {output_file}")
        except Exception as e:
            self.log_message(f"Decryption error: {str(e)}")
            messagebox.showerror("Error", f"Decryption failed: {str(e)}")

if __name__ == "__main__":
    root = tk.Tk()
    app = FileEncryptorApp(root)
    root.mainloop()
