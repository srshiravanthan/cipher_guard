"""
CipherGuard - Folder Encryption/Decryption Tool
Copyright (c) 2025 SR Shiravanthan
Licensed under the MIT License
"""



import tkinter as tk
from tkinter import filedialog, messagebox
import webbrowser
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, NoEncryption
import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
import zipfile
from argon2 import PasswordHasher
from argon2.low_level import hash_secret_raw, Type
import shutil

class CustomFrame(tk.Frame):
    def __init__(self, master=None, **kwargs):
        super().__init__(master, **kwargs)
        self.config(bg='black')

class FolderEncryptDecryptApp:
    def __init__(self, master):
        self.master = master
        self.master.title("Folder Encryption/Decryption")
        self.master.configure(bg='black')
        self.sender_email = tk.StringVar()
        self.recipient_email = tk.StringVar()
        self.folder_path = tk.StringVar()
        self.password = tk.StringVar()
        self.gmail_password = tk.StringVar()

        title_label = tk.Label(master, text="CipherGuard", font=("Helvetica", 16, "bold"), fg="white", bg="black")
        title_label.grid(row=0, columnspan=4, pady=10)

        tk.Label(master, text="Sender Email:", fg="white", bg="black").grid(row=1, column=0, sticky="e", padx=10, pady=10)
        tk.Entry(master, textvariable=self.sender_email, width=40).grid(row=1, column=1, columnspan=2, padx=10, pady=10)

        tk.Label(master, text="Recipient Email:", fg="white", bg="black").grid(row=2, column=0, sticky="e", padx=10, pady=10)
        tk.Entry(master, textvariable=self.recipient_email, width=40).grid(row=2, column=1, columnspan=2, padx=10, pady=10)

        tk.Label(master, text="Gmail Password:", fg="white", bg="black").grid(row=3, column=0, sticky="e", padx=10, pady=10)
        tk.Entry(master, textvariable=self.gmail_password, show="*", width=40).grid(row=3, column=1, columnspan=2, padx=10, pady=10)

        tk.Label(master, text="Folder Path:", fg="white", bg="black").grid(row=4, column=0, sticky="e", padx=10, pady=10)
        tk.Entry(master, textvariable=self.folder_path, width=40).grid(row=4, column=1, columnspan=2, padx=10, pady=10)
        tk.Button(master, text="Browse", command=self.browse_folder).grid(row=4, column=3, padx=10, pady=10)

        tk.Label(master, text="Password:", fg="white", bg="black").grid(row=5, column=0, sticky="e", padx=10, pady=10)
        tk.Entry(master, textvariable=self.password, show="*", width=40).grid(row=5, column=1, columnspan=2, padx=10, pady=10)

        tk.Button(master, text="Encrypt", command=self.encrypt_folder, bg='green', fg='white').grid(row=6, column=1, padx=10, pady=10)
        tk.Button(master, text="Decrypt", command=self.decrypt_folder, bg='green', fg='white').grid(row=6, column=2, padx=10, pady=10)


        self.private_key, self.public_key = self.generate_keys()

    def browse_folder(self):
        folder_selected = filedialog.askdirectory()
        if folder_selected:
            self.folder_path.set(folder_selected)

    def derive_key(self, password, salt):
        key = hash_secret_raw(
            secret=password.encode('utf-8'),
            salt=salt,
            time_cost=4,
            memory_cost=1024 * 64,
            parallelism=2,
            hash_len=32,
            type=Type.ID
        )
        return key

    def encrypt_file(self, file_path, key, encrypted_folder):
        with open(file_path, 'rb') as file:
            plaintext = file.read()

        cipher = Cipher(algorithms.AES(key), modes.GCM(b'\0' * 12), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()

        tag = encryptor.tag

        encrypted_file_path = os.path.join(encrypted_folder, os.path.basename(file_path) + '.enc')
        with open(encrypted_file_path, 'wb') as encrypted_file:
            encrypted_file.write(ciphertext + tag)

        return encrypted_file_path

    def decrypt_file(self, encrypted_file_path, key):
        with open(encrypted_file_path, 'rb') as file:
            data = file.read()

        ciphertext = data[:-16]
        tag = data[-16:]

        cipher = Cipher(algorithms.AES(key), modes.GCM(b'\0' * 12, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        original_file_path = encrypted_file_path.rstrip('.enc')
        with open(original_file_path, 'wb') as decrypted_file:
            decrypted_file.write(plaintext)

    def generate_keys(self):
        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        public_key = private_key.public_key()
        return private_key, public_key

    def sign_data(self, data):
        signature = self.private_key.sign(data, ec.ECDSA(hashes.SHA256()))
        return signature

    def verify_signature(self, data, signature):
        self.public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))

    def encrypt_folder(self):
        sender_email = self.sender_email.get()
        recipient_email = self.recipient_email.get()
        folder_path = self.folder_path.get()
        password = self.password.get()
        gmail_password = self.gmail_password.get()

        if not os.path.exists(folder_path):
            messagebox.showerror("Error", "Invalid folder path.")
            return

        # Create a salt file
        salt = os.urandom(16)
        salt_file_path = os.path.join(folder_path, '.salt')
        with open(salt_file_path, 'wb') as salt_file:
            salt_file.write(salt)

        # Derive key from password and salt
        key = self.derive_key(password, salt)

        # Create a new folder for the encrypted files
        encrypted_folder = folder_path + '_encrypted'
        if not os.path.exists(encrypted_folder):
            os.makedirs(encrypted_folder)

        # Encrypt each file in the folder and place it in the new encrypted folder
        for root, dirs, files in os.walk(folder_path):
            for file in files:
                file_path = os.path.join(root, file)
                if not file_path.endswith('.salt'):
                    encrypted_file_path = self.encrypt_file(file_path, key, encrypted_folder)

                    # Generate HMAC
                    h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
                    with open(encrypted_file_path, 'rb') as f:
                        h.update(f.read())
                    hmac_value = h.finalize()
                    hmac_path = encrypted_file_path + '.hmac'
                    with open(hmac_path, 'wb') as f:
                        f.write(hmac_value)

                    # Sign the HMAC
                    signature = self.sign_data(hmac_value)
                    sig_path = encrypted_file_path + '.sig'
                    with open(sig_path, 'wb') as f:
                        f.write(signature)

        # Add the salt file to the encrypted folder
        shutil.copy2(salt_file_path, encrypted_folder)

        # Create a zip file containing the encrypted folder
        zip_file_path = encrypted_folder + '.zip'
        with zipfile.ZipFile(zip_file_path, 'w') as zipf:
            for root, dirs, files in os.walk(encrypted_folder):
                for file in files:
                    file_path = os.path.join(root, file)
                    zipf.write(file_path, os.path.relpath(file_path, encrypted_folder))

        # Send email notification with the encrypted folder as an attachment
        self.send_email_notification(sender_email, recipient_email, 'Folder encrypted successfully.', password, gmail_password, zip_file_path)
        messagebox.showinfo("Success", "Folder encrypted successfully.")

    def decrypt_folder(self):
        sender_email = self.sender_email.get()
        recipient_email = self.recipient_email.get()
        folder_path = self.folder_path.get()
        password = self.password.get()
        gmail_password = self.gmail_password.get()

        if not os.path.exists(folder_path):
            messagebox.showerror("Error", "Invalid folder path.")
            return

        try:
            with open(os.path.join(folder_path, '.salt'), 'rb') as salt_file:
                salt = salt_file.read()
        except FileNotFoundError:
            messagebox.showerror("Error", "Salt file not found. Folder may not be encrypted.")
            return

        key = self.derive_key(password, salt)

        for root, dirs, files in os.walk(folder_path):
            for file in files:
                if file.endswith('.enc'):
                    encrypted_file_path = os.path.join(root, file)
                    hmac_path = encrypted_file_path + '.hmac'
                    sig_path = encrypted_file_path + '.sig'

                    # Verify the signature
                    try:
                        with open(hmac_path, 'rb') as f:
                            hmac_value = f.read()
                    except FileNotFoundError:
                        messagebox.showerror("Error", f"HMAC file not found: {hmac_path}")
                        return

                    try:
                        with open(sig_path, 'rb') as f:
                            signature = f.read()
                    except FileNotFoundError:
                        messagebox.showerror("Error", f"Signature file not found: {sig_path}")
                        return

                    try:
                        self.verify_signature(hmac_value, signature)
                    except Exception as e:
                        messagebox.showerror("Error", f"Signature verification failed: {e}")
                        return

                    # Verify the HMAC
                    try:
                        h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
                        with open(encrypted_file_path, 'rb') as f:
                            h.update(f.read())
                        h.verify(hmac_value)
                    except Exception as e:
                        messagebox.showerror("Error", f"HMAC verification failed: {e}")
                        return

                    self.decrypt_file(encrypted_file_path, key)
                    os.remove(encrypted_file_path)
                    os.remove(hmac_path)
                    os.remove(sig_path)

        self.send_email_notification(sender_email, recipient_email, 'Folder decrypted successfully.', password, gmail_password)
        messagebox.showinfo("Success", "Folder decrypted successfully.")

    def send_email_notification(self, sender_email, recipient_email, subject, password, gmail_password, attachment_path=None):
        msg = MIMEMultipart()
        msg['From'] = sender_email
        msg['To'] = recipient_email
        msg['Subject'] = subject

        body = MIMEText(f'The operation "{subject}" has been completed successfully.\n Your password is: {password}', 'plain')
        msg.attach(body)

        if attachment_path:
            with open(attachment_path, 'rb') as f:
                part = MIMEApplication(f.read(), Name=os.path.basename(attachment_path))
                part['Content-Disposition'] = f'attachment; filename="{os.path.basename(attachment_path)}"'
                msg.attach(part)

        try:
            server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
            server.login(sender_email, gmail_password)
            server.sendmail(sender_email, recipient_email, msg.as_string())
            server.close()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to send email: {e}")

if __name__ == "__main__":
    root = tk.Tk()
    app = FolderEncryptDecryptApp(root)
    root.mainloop()
