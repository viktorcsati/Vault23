import hashlib
import os
import getpass
import re
import json
import base64
import secrets
import string
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

PASSWORD_FILE = "password.txt"
VAULT_FILE = "secrets.enc"

class PasswordManager:
    def __init__(self, password_file=PASSWORD_FILE, vault_file=VAULT_FILE):
        self.password_file = password_file
        self.vault_file = vault_file
        self.vault = {}
        self.master_password = None

    def hash_password(self, password: str) -> str:
        return hashlib.sha256(password.encode('utf-8')).hexdigest()

    def complexity_check(self, password: str) -> bool:
        if (len(password) < 8 or
            not re.search(r"[A-Z]", password) or
            not re.search(r"[a-z]", password) or
            not re.search(r"[0-9]", password) or
            not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password)):
            return False
        return True

    def derive_key(self, password: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))

    def load_vault(self, password: str) -> bool:
        if not os.path.exists(self.vault_file):
            self.vault = {}
            self.master_password = password
            return True
        
        try:
            with open(self.vault_file, 'rb') as f:
                data = f.read()
                if not data:
                    self.vault = {}
                    self.master_password = password
                    return True
                # First 16 bytes are the salt
                salt = data[:16]
                ciphertext = data[16:]
                
                key = self.derive_key(password, salt)
                f = Fernet(key)
                decrypted_data = f.decrypt(ciphertext)
                self.vault = json.loads(decrypted_data.decode())
                self.master_password = password
                return True
        except (InvalidToken, ValueError):
            return False

    def save_vault(self):
        if self.master_password is None:
            raise ValueError("Vault not loaded or master password not set")
        
        salt = os.urandom(16)
        key = self.derive_key(self.master_password, salt)
        f = Fernet(key)
        
        json_data = json.dumps(self.vault).encode()
        ciphertext = f.encrypt(json_data)
        
        with open(self.vault_file, 'wb') as f:
            f.write(salt + ciphertext)

    def is_setup(self) -> bool:
        return os.path.exists(self.password_file) and os.path.getsize(self.password_file) > 0

    def setup_master_password(self, password: str):
        hashed_pw = self.hash_password(password)
        with open(self.password_file, 'w') as f:
            f.write(hashed_pw)
        self.master_password = password
        self.save_vault()

    def verify_master_password(self, password: str) -> bool:
        if not self.is_setup():
            return False
        with open(self.password_file, 'r') as f:
            stored_hashed_pw = f.read().strip()
        return self.hash_password(password) == stored_hashed_pw

    def add_credential(self, service, username, password):
        self.vault[service] = {'username': username, 'password': password}
        self.save_vault()

    def get_credential(self, service):
        return self.vault.get(service)

    def delete_credential(self, service):
        if service in self.vault:
            del self.vault[service]
            self.save_vault()
            return True
        return False

    def list_services(self):
        return list(self.vault.keys())

    def change_master_password(self, current_pw, new_pw):
        if not self.verify_master_password(current_pw):
            return False
        
        # Update password.txt
        hashed_new_pw = self.hash_password(new_pw)
        with open(self.password_file, 'w') as f:
            f.write(hashed_new_pw)
            
        # Re-encrypt vault with new password
        self.master_password = new_pw
        self.save_vault()
        return True

    def generate_password(self, length=16, use_upper=True, use_digits=True, use_special=True) -> str:
        chars = string.ascii_lowercase
        if use_upper:
            chars += string.ascii_uppercase
        if use_digits:
            chars += string.digits
        if use_special:
            chars += string.punctuation

        if not chars:
            raise ValueError("At least one character set must be selected")

        return ''.join(secrets.choice(chars) for _ in range(length))

def main():
    pm = PasswordManager()
    
    # 1. Authenticate or Setup Master Password
    if not pm.is_setup():
        print("--- Setup Master Password ---")
        while True:
            pw = getpass.getpass("Create a new master password: ")
            if not pm.complexity_check(pw):
                print("Password does not meet complexity requirements (8+ chars, upper, lower, digit, special).")
                continue
            confirm_pw = getpass.getpass("Confirm master password: ")
            if pw != confirm_pw:
                print("Passwords do not match.")
                continue
            
            pm.setup_master_password(pw)
            print("Master password set successfully.")
            break
    else:
        print("--- Login ---")
        attempts = 3
        while attempts > 0:
            pw = getpass.getpass("Enter master password: ")
            if pm.verify_master_password(pw):
                if pm.load_vault(pw):
                    print("Login successful.")
                    break
                else:
                    print("Error: Failed to decrypt vault with correct password logic. Data corruption?")
                    exit(1)
            else:
                attempts -= 1
                print(f"Incorrect password. {attempts} attempts remaining.")
        else:
            print("Too many incorrect attempts. Exiting.")
            exit(1)

    # 3. Main Menu
    while True:
        print("\n--- Password Manager ---")
        print("1. Add Credential")
        print("2. Get Credential")
        print("3. List Services")
        print("4. Change Master Password")
        print("5. Exit")
        
        choice = input("Select an option: ").strip()
        
        if choice == '1':
            service = input("Service: ").strip()
            if not service:
                print("Service name cannot be empty.")
                continue
            username = input("Username: ").strip()
            password_cred = getpass.getpass("Password: ")
            
            pm.add_credential(service, username, password_cred)
            print(f"Credential for {service} saved.")
            
        elif choice == '2':
            service = input("Service to retrieve: ").strip()
            cred = pm.get_credential(service)
            if cred:
                print(f"Service: {service}")
                print(f"Username: {cred['username']}")
                print(f"Password: {cred['password']}")
            else:
                print("Service not found.")
                
        elif choice == '3':
            services = pm.list_services()
            if not services:
                print("No services stored.")
            else:
                print("Stored Services:")
                for service in services:
                    print(f"- {service}")
                    
        elif choice == '4':
            current_pw = getpass.getpass("Enter current master password: ")
            new_pw = getpass.getpass("Enter new master password: ")
            if not pm.complexity_check(new_pw):
                print("New password does not meet complexity requirements.")
                continue
            confirm_new_pw = getpass.getpass("Confirm new master password: ")
            if new_pw != confirm_new_pw:
                print("Passwords do not match.")
                continue
            
            if pm.change_master_password(current_pw, new_pw):
                print("Master password changed and vault re-encrypted.")
            else:
                print("Incorrect current password.")
            
        elif choice == '5':
            print("Exiting.")
            break
        else:
            print("Invalid option.")
