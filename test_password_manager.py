import unittest
import os
import json
from password_manager import PasswordManager, VAULT_FILE, PASSWORD_FILE

class TestPasswordManager(unittest.TestCase):
    def setUp(self):
        # Clean up before tests
        if os.path.exists(VAULT_FILE):
            os.remove(VAULT_FILE)
        if os.path.exists(PASSWORD_FILE):
            os.remove(PASSWORD_FILE)
        self.pm = PasswordManager()

    def tearDown(self):
        # Clean up after tests
        if os.path.exists(VAULT_FILE):
            os.remove(VAULT_FILE)
        if os.path.exists(PASSWORD_FILE):
            os.remove(PASSWORD_FILE)

    def test_derive_key(self):
        password = "TestPassword123!"
        salt = b'1234567890123456'
        key1 = self.pm.derive_key(password, salt)
        key2 = self.pm.derive_key(password, salt)
        self.assertEqual(key1, key2)
        self.assertIsInstance(key1, bytes)

    def test_save_and_load_vault(self):
        password = "TestPassword123!"
        self.pm.setup_master_password(password)
        
        self.pm.add_credential("google", "user", "pw")
        self.assertTrue(os.path.exists(VAULT_FILE))
        
        # Create new instance to simulate restart
        pm2 = PasswordManager()
        success = pm2.load_vault(password)
        self.assertTrue(success)
        self.assertEqual(pm2.get_credential("google"), {"username": "user", "password": "pw"})

    def test_load_vault_wrong_password(self):
        password = "TestPassword123!"
        wrong_password = "WrongPassword123!"
        self.pm.setup_master_password(password)
        
        pm2 = PasswordManager()
        success = pm2.load_vault(wrong_password)
        self.assertFalse(success)

    def test_load_nonexistent_vault(self):
        success = self.pm.load_vault("any_password")
        self.assertTrue(success) # Should return empty vault
        self.assertEqual(self.pm.vault, {})

    def test_generate_password(self):
        # Test default
        pw = self.pm.generate_password()
        self.assertEqual(len(pw), 16)
        
        # Test custom length
        pw = self.pm.generate_password(length=20)
        self.assertEqual(len(pw), 20)
        
        # Test character sets
        pw = self.pm.generate_password(length=100, use_upper=False, use_digits=False, use_special=False)
        self.assertTrue(pw.islower())
        self.assertFalse(any(c.isupper() for c in pw))
        self.assertFalse(any(c.isdigit() for c in pw))
        
        # Test error - NOT APPLICABLE as lowercase is always included
        # with self.assertRaises(ValueError):
        #     self.pm.generate_password(use_upper=False, use_digits=False, use_special=False, length=10)
        pass

    def test_delete_credential(self):
        password = "TestPassword123!"
        self.pm.setup_master_password(password)
        
        self.pm.add_credential("google", "user", "pw")
        self.assertIsNotNone(self.pm.get_credential("google"))
        
        # Delete existing
        result = self.pm.delete_credential("google")
        self.assertTrue(result)
        self.assertIsNone(self.pm.get_credential("google"))
        
        # Delete non-existent
        result = self.pm.delete_credential("yahoo")
        self.assertFalse(result)


if __name__ == '__main__':
    unittest.main()
