import hashlib
import os
import getpass
PATH = "password.txt"
def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode('utf-8')).hexdigest()
if not os.path.exists(PATH) or os.path.getsize(PATH) == 0:
    # File missing or empty -> set a new password
    pw=getpass.getpass("No password set. Please create a new password.")
    confirm_pw=getpass.getpass("Please confirm your new password.")
    if pw != confirm_pw:
        print("Password does not match. Exiting.")
        exit(1)
    else:
        hashed_pw = hash_password(pw)
        with open(PATH, 'w') as f:
            f.write(hashed_pw)
        print("Password set successfully.")
else:
    # File exists -> verify password
    stored_hashed_pw = ""
    with open(PATH, 'r') as f:
        stored_hashed_pw = f.read().strip()
    pw=getpass.getpass("Enter your password:")
    hashed_pw = hash_password(pw)
    if hashed_pw == stored_hashed_pw:
        print("Access granted.")
    else:
        print("Access denied. Incorrect password.")
print("Do you want to change your password? (yes/no)")
if input().lower() == 'yes':
    current_pw=getpass.getpass("Enter your current password:")
    if hash_password(current_pw) != stored_hashed_pw:
        print("Incorrect current password. Exiting.")
        exit(1)
    new_pw=getpass.getpass("Enter your new password:")
    confirm_new_pw=getpass.getpass("Confirm your new password:")
    if new_pw != confirm_new_pw:
        print("New passwords do not match. Exiting.")
        exit(1)
    new_hashed_pw = hash_password(new_pw)
    with open(PATH, 'w') as f:
        f.write(new_hashed_pw)
        print("Password changed successfully.")
