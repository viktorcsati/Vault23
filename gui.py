import sys
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QHBoxLayout, QLabel, QLineEdit, QPushButton, 
                             QTableWidget, QTableWidgetItem, QMessageBox, QHeaderView,
                             QInputDialog, QDialog, QFormLayout, QSpinBox, QCheckBox,
                             QDialogButtonBox)
from PyQt6.QtCore import Qt
from password_manager import PasswordManager

class LoginWindow(QWidget):
    def __init__(self, pm):
        super().__init__()
        self.pm = pm
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("Password Manager - Login")
        self.setGeometry(100, 100, 300, 150)
        
        layout = QVBoxLayout()
        
        self.label = QLabel("Enter Master Password:")
        layout.addWidget(self.label)
        
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addWidget(self.password_input)
        
        self.login_btn = QPushButton("Login")
        self.login_btn.clicked.connect(self.handle_login)
        layout.addWidget(self.login_btn)
        
        if not self.pm.is_setup():
            self.label.setText("Setup Master Password:")
            self.login_btn.setText("Setup")
            
        self.setLayout(layout)

    def handle_login(self):
        password = self.password_input.text()
        if not password:
            return

        if not self.pm.is_setup():
            # Setup mode
            if not self.pm.complexity_check(password):
                QMessageBox.warning(self, "Error", "Password does not meet complexity requirements.")
                return
            
            # Confirm password
            confirm, ok = QInputDialog.getText(self, "Confirm Password", "Confirm Master Password:", QLineEdit.EchoMode.Password)
            if ok and confirm == password:
                self.pm.setup_master_password(password)
                QMessageBox.information(self, "Success", "Master password set successfully.")
                self.open_main_window()
            else:
                QMessageBox.warning(self, "Error", "Passwords do not match.")
        else:
            # Login mode
            if self.pm.verify_master_password(password):
                if self.pm.load_vault(password):
                    self.open_main_window()
                else:
                    QMessageBox.critical(self, "Error", "Failed to load vault.")
            else:
                QMessageBox.warning(self, "Error", "Incorrect password.")

    def open_main_window(self):
        self.main_window = MainWindow(self.pm)
        self.main_window.show()
        self.close()

class PasswordGeneratorDialog(QDialog):
    def __init__(self, pm, parent=None):
        super().__init__(parent)
        self.pm = pm
        self.generated_password = ""
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("Password Generator")
        layout = QVBoxLayout()

        # Settings
        form_layout = QFormLayout()
        
        self.length_spin = QSpinBox()
        self.length_spin.setRange(4, 64)
        self.length_spin.setValue(16)
        form_layout.addRow("Length:", self.length_spin)
        
        self.upper_check = QCheckBox("Uppercase (A-Z)")
        self.upper_check.setChecked(True)
        form_layout.addRow(self.upper_check)
        
        self.digits_check = QCheckBox("Digits (0-9)")
        self.digits_check.setChecked(True)
        form_layout.addRow(self.digits_check)
        
        self.special_check = QCheckBox("Special (!@#...)")
        self.special_check.setChecked(True)
        form_layout.addRow(self.special_check)
        
        layout.addLayout(form_layout)

        # Result display
        self.result_edit = QLineEdit()
        self.result_edit.setReadOnly(True)
        layout.addWidget(self.result_edit)

        # Buttons
        btn_layout = QHBoxLayout()
        
        generate_btn = QPushButton("Generate")
        generate_btn.clicked.connect(self.generate)
        btn_layout.addWidget(generate_btn)
        
        use_btn = QPushButton("Use Password")
        use_btn.clicked.connect(self.accept)
        btn_layout.addWidget(use_btn)
        
        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(self.reject)
        btn_layout.addWidget(cancel_btn)
        
        layout.addLayout(btn_layout)
        self.setLayout(layout)
        
        # Generate initial password
        self.generate()

    def generate(self):
        try:
            pw = self.pm.generate_password(
                length=self.length_spin.value(),
                use_upper=self.upper_check.isChecked(),
                use_digits=self.digits_check.isChecked(),
                use_special=self.special_check.isChecked()
            )
            self.result_edit.setText(pw)
            self.generated_password = pw
        except ValueError as e:
            QMessageBox.warning(self, "Error", str(e))

    def get_password(self):
        return self.generated_password

class MainWindow(QMainWindow):
    def __init__(self, pm):
        super().__init__()
        self.pm = pm
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("Password Manager")
        self.setGeometry(100, 100, 600, 400)
        
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)
        
        # Buttons
        btn_layout = QHBoxLayout()
        
        add_btn = QPushButton("Add Credential")
        add_btn.clicked.connect(self.add_credential)
        btn_layout.addWidget(add_btn)
        
        refresh_btn = QPushButton("Refresh")
        refresh_btn.clicked.connect(self.populate_table)
        btn_layout.addWidget(refresh_btn)
        
        change_pw_btn = QPushButton("Change Master Password")
        change_pw_btn.clicked.connect(self.change_master_password)
        btn_layout.addWidget(change_pw_btn)

        layout.addLayout(btn_layout)
        
        # Table
        self.table = QTableWidget()
        self.table.setColumnCount(3)
        self.table.setHorizontalHeaderLabels(["Service", "Username", "Password"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.table.cellDoubleClicked.connect(self.copy_password)
        layout.addWidget(self.table)
        
        self.populate_table()

    def populate_table(self):
        services = self.pm.list_services()
        self.table.setRowCount(len(services))
        
        for i, service in enumerate(services):
            cred = self.pm.get_credential(service)
            self.table.setItem(i, 0, QTableWidgetItem(service))
            self.table.setItem(i, 1, QTableWidgetItem(cred['username']))
            self.table.setItem(i, 2, QTableWidgetItem("********")) # Hide password

    def add_credential(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("Add Credential")
        layout = QFormLayout(dialog)
        
        service_input = QLineEdit()
        username_input = QLineEdit()
        
        password_layout = QHBoxLayout()
        password_input = QLineEdit()
        password_input.setEchoMode(QLineEdit.EchoMode.Password)
        password_layout.addWidget(password_input)
        
        gen_btn = QPushButton("Generate")
        def open_generator():
            gen_dialog = PasswordGeneratorDialog(self.pm, dialog)
            if gen_dialog.exec() == QDialog.DialogCode.Accepted:
                password_input.setText(gen_dialog.get_password())
                password_input.setEchoMode(QLineEdit.EchoMode.Normal) # Show generated password temporarily? Or keep hidden?
                # Let's keep it hidden but maybe toggle visibility? For now standard behavior.
        
        gen_btn.clicked.connect(open_generator)
        password_layout.addWidget(gen_btn)
        
        layout.addRow("Service:", service_input)
        layout.addRow("Username:", username_input)
        layout.addRow("Password:", password_layout)
        
        btn = QPushButton("Save")
        btn.clicked.connect(dialog.accept)
        layout.addRow(btn)
        
        if dialog.exec() == QDialog.DialogCode.Accepted:
            service = service_input.text().strip()
            username = username_input.text().strip()
            password = password_input.text()
            
            if service and username and password:
                self.pm.add_credential(service, username, password)
                self.populate_table()
            else:
                QMessageBox.warning(self, "Error", "All fields are required.")

    def copy_password(self, row, column):
        if column == 2: # Password column
            service = self.table.item(row, 0).text()
            cred = self.pm.get_credential(service)
            clipboard = QApplication.clipboard()
            clipboard.setText(cred['password'])
            QMessageBox.information(self, "Copied", f"Password for {service} copied to clipboard.")

    def change_master_password(self):
        current_pw, ok1 = QInputDialog.getText(self, "Change Password", "Current Password:", QLineEdit.EchoMode.Password)
        if not ok1: return
        
        new_pw, ok2 = QInputDialog.getText(self, "Change Password", "New Password:", QLineEdit.EchoMode.Password)
        if not ok2: return
        
        if not self.pm.complexity_check(new_pw):
             QMessageBox.warning(self, "Error", "New password does not meet complexity requirements.")
             return

        confirm_pw, ok3 = QInputDialog.getText(self, "Change Password", "Confirm New Password:", QLineEdit.EchoMode.Password)
        if not ok3: return
        
        if new_pw != confirm_pw:
            QMessageBox.warning(self, "Error", "New passwords do not match.")
            return
            
        if self.pm.change_master_password(current_pw, new_pw):
            QMessageBox.information(self, "Success", "Master password changed successfully.")
        else:
            QMessageBox.warning(self, "Error", "Incorrect current password.")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    pm = PasswordManager()
    window = LoginWindow(pm)
    window.show()
    sys.exit(app.exec())
