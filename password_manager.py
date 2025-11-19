import hashlib
import os
import getpass
import re
import json
import base64
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

PASSWORD_FILE = "password.txt"
VAULT_FILE = "secrets.enc"

# Hashing function for master password verification
def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

# Password complexity check
def complexity_check(password: str) -> bool:
    if (len(password) < 8 or
        not re.search(r"[A-Z]", password) or
        not re.search(r"[a-z]", password) or
        not re.search(r"[0-9]", password) or
        not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password)):
        return False
    return True

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def load_vault(password: str):
    if not os.path.exists(VAULT_FILE):
        return {}
    
    try:
        with open(VAULT_FILE, 'rb') as f:
            data = f.read()
            if not data:
                return {}
            # First 16 bytes are the salt
            salt = data[:16]
            ciphertext = data[16:]
            
            key = derive_key(password, salt)
            f = Fernet(key)
            decrypted_data = f.decrypt(ciphertext)
            return json.loads(decrypted_data.decode())
    except (InvalidToken, ValueError):
        # InvalidToken: wrong password
        # ValueError: could happen if file is corrupted or empty
        return None

def save_vault(vault_data: dict, password: str):
    salt = os.urandom(16)
    key = derive_key(password, salt)
    f = Fernet(key)
    
    json_data = json.dumps(vault_data).encode()
    ciphertext = f.encrypt(json_data)
    
    with open(VAULT_FILE, 'wb') as f:
        f.write(salt + ciphertext)

def main():
    # 1. Authenticate or Setup Master Password
    if not os.path.exists(PASSWORD_FILE) or os.path.getsize(PASSWORD_FILE) == 0:
        print("--- Setup Master Password ---")
        while True:
            pw = getpass.getpass("Create a new master password: ")
            if not complexity_check(pw):
                print("Password does not meet complexity requirements (8+ chars, upper, lower, digit, special).")
                continue
            confirm_pw = getpass.getpass("Confirm master password: ")
            if pw != confirm_pw:
                print("Passwords do not match.")
                continue
            
            hashed_pw = hash_password(pw)
            with open(PASSWORD_FILE, 'w') as f:
                f.write(hashed_pw)
            print("Master password set successfully.")
            
            # Initialize empty vault
            save_vault({}, pw)
            break
    else:
        print("--- Login ---")
        with open(PASSWORD_FILE, 'r') as f:
            stored_hashed_pw = f.read().strip()
        
        attempts = 3
        while attempts > 0:
            pw = getpass.getpass("Enter master password: ")
            if hash_password(pw) == stored_hashed_pw:
                print("Login successful.")
                break
            else:
                attempts -= 1
                print(f"Incorrect password. {attempts} attempts remaining.")
        else:
            print("Too many incorrect attempts. Exiting.")
            exit(1)

    # 2. Load Vault
    # We use the 'pw' variable from the login/setup block
    vault = load_vault(pw)
    if vault is None:
        print("Error: Failed to decrypt vault. Did the master password change without updating the vault?")
        # This might happen if someone manually changed password.txt but not secrets.enc
        # For now, we exit to be safe.
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
            
            vault[service] = {'username': username, 'password': password_cred}
            save_vault(vault, pw)
            print(f"Credential for {service} saved.")
            
        elif choice == '2':
            service = input("Service to retrieve: ").strip()
            if service in vault:
                cred = vault[service]
                print(f"Service: {service}")
                print(f"Username: {cred['username']}")
                print(f"Password: {cred['password']}")
            else:
                print("Service not found.")
                
        elif choice == '3':
            if not vault:
                print("No services stored.")
            else:
                print("Stored Services:")
                for service in vault:
                    print(f"- {service}")
                    
        elif choice == '4':
            current_pw = getpass.getpass("Enter current master password: ")
            if hash_password(current_pw) != stored_hashed_pw:
                print("Incorrect current password.")
                continue
                
            new_pw = getpass.getpass("Enter new master password: ")
            if not complexity_check(new_pw):
                print("New password does not meet complexity requirements.")
                continue
            confirm_new_pw = getpass.getpass("Confirm new master password: ")
            if new_pw != confirm_new_pw:
                print("Passwords do not match.")
                continue
            
            # Update password.txt
            new_hashed_pw = hash_password(new_pw)
            with open(PASSWORD_FILE, 'w') as f:
                f.write(new_hashed_pw)
                
            # Re-encrypt vault with new password
            save_vault(vault, new_pw)
            
            # Update local variables
            pw = new_pw
            stored_hashed_pw = new_hashed_pw
            print("Master password changed and vault re-encrypted.")
            
        elif choice == '5':
            print("Exiting.")
            break
        else:
            print("Invalid option.")

if __name__ == "__main__":
    main()
