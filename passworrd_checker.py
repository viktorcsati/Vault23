import hashlib
import os
import getpass
import re

PATH = "password.txt"

# Hashing function
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

# Main logic
if not os.path.exists(PATH) or os.path.getsize(PATH) == 0:
    # File missing or empty -> set a new password
    while True:
        pw=getpass.getpass("No password set. Please create a new password.")
        if not complexity_check(pw):
            print("Password does not meet complexity requirements.")
            continue
        confirm_pw=getpass.getpass("Please confirm your new password.")
        if pw != confirm_pw:
            print("Password does not match. Exiting.")
            continue
        else:
            hashed_pw = hash_password(pw)
            with open(PATH, 'w') as f:
                f.write(hashed_pw)
            print("Password set successfully.")
            break
else:
    # File exists -> verify password
    stored_hashed_pw = ""
    with open(PATH, 'r') as f:
        stored_hashed_pw = f.read().strip()
    attempts = 3
    while attempts > 0:
        pw=getpass.getpass("Enter your password:")
        if hash_password(pw) == stored_hashed_pw:
            print("Correct password. Welcome!")
            break
        else:
            attempts -= 1
            print("Incorrect password.")
    else:
        print("Too many incorrect attempts. Exiting.")
        exit(1)

    print("Do you want to change your password? (yes/no)")
    answer = input().strip().lower()
    if answer == 'yes':
        # Change password process
        current_pw=getpass.getpass("Enter your current password:")
        if hash_password(current_pw) != stored_hashed_pw:
            print("Incorrect current password.")
            exit(1)
        new_pw=getpass.getpass("Enter your new password:")
        if not complexity_check(new_pw):
            print("New password does not meet complexity requirements.")
            exit(1)
        confirm_new_pw=getpass.getpass("Confirm your new password:")
        if new_pw != confirm_new_pw:
            print("New passwords do not match.")
            exit(1)
        new_hashed_pw = hash_password(new_pw)
        with open(PATH, 'w') as f:
            f.write(new_hashed_pw)
            print("Password changed successfully.")
    elif answer == 'no':
        print("Password change cancelled. Goodbye!")
