import sys
import mysql.connector
from pymongo import MongoClient
from bson.objectid import ObjectId
import hashlib      # For calculating file hash
import subprocess   # To run Ingestor.py
import os           # To check file existence
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
                             QLabel, QLineEdit, QPushButton, QTableWidget, QTableWidgetItem, 
                             QHeaderView, QMessageBox, QTabWidget, QDialog, QFormLayout, 
                             QComboBox, QFrame, QAbstractItemView, QInputDialog)
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QFont, QIcon

# --- CONFIGURATION ---
DB_CONFIG = {
    "host": "localhost",
    "user": "root",
    "password": "thebe", 
    "database": "suricata_db"
}

# --- AUTO-INGESTION CONFIG ---
LOG_FILE_PATH = "/var/log/suricata/eve.json"
HASH_FILE_PATH = "/var/log/suricata/evehash.txt"
INGESTOR_SCRIPT = "Ingestor.py"  # Assumes script is in the same folder

# --- STYLESHEET (Dark Cyber Theme) ---
DARK_STYLESHEET = """
QWidget { 
    background-color: #1e1e1e; 
    color: #e0e0e0; 
    font-family: 'Segoe UI', sans-serif; 
    font-size: 14px; 
}
QDialog { background-color: #1e1e1e; }
QLabel { color: #e0e0e0; font-weight: bold; }
QLineEdit { 
    background-color: #333333; 
    border: 1px solid #555555; 
    border-radius: 3px;
    padding: 5px; 
    color: white; 
}
QTableWidget { 
    background-color: #252526; 
    gridline-color: #3e3e42; 
    border: 1px solid #3e3e42;
    selection-background-color: #007acc; 
    selection-color: white;
}
QTableWidget::item:selected {
    background-color: #007acc;
    color: white;
}
QHeaderView::section { 
    background-color: #333337; 
    padding: 5px; 
    border: 1px solid #3e3e42; 
    font-weight: bold;
    color: #cccccc;
}
QPushButton { 
    background-color: #0e639c; 
    color: white; 
    border: none; 
    padding: 8px 15px; 
    border-radius: 4px;
    font-weight: bold;
}
QPushButton:hover { background-color: #1177bb; }
QPushButton:pressed { background-color: #094771; }
QPushButton#DangerBtn { background-color: #d83b01; }
QPushButton#DangerBtn:hover { background-color: #f8511b; }
QPushButton#SuccessBtn { background-color: #2da44e; }
QPushButton#SuccessBtn:hover { background-color: #2c974b; }
QPushButton#WarningBtn { background-color: #d19a0a; color: white; }
QPushButton#WarningBtn:hover { background-color: #f5b914; }
QComboBox {
    background-color: #333333;
    border: 1px solid #555555;
    color: white;
    padding: 5px;
}
QTabWidget::pane { border: 1px solid #3e3e42; }
QTabBar::tab { 
    background-color: #2d2d30; 
    padding: 8px 20px; 
    color: #e0e0e0; 
    border-top-left-radius: 4px;
    border-top-right-radius: 4px;
}
QTabBar::tab:selected { 
    background-color: #1e1e1e; 
    border-top: 3px solid #007acc; 
    font-weight: bold;
}
"""

# --- DATABASE MANAGER ---
class DbManager:
    def __init__(self):
        try:
            # Using Authentication for MongoDB
            self.mongo_client = MongoClient("mongodb://admin:thebe@localhost:27017/?authSource=admin")
            self.mongo_db = self.mongo_client["suricata_db"]
            self.mongo_col = self.mongo_db["raw_logs"]
        except Exception as e:
            print(f"MongoDB Error: {e}")

    def get_sql_connection(self):
        try:
            return mysql.connector.connect(**DB_CONFIG)
        except Exception as e:
            print(f"MySQL Error: {e}")
            return None

    def query_sql(self, query, params=(), fetch=False):
        conn = self.get_sql_connection()
        if not conn: return None
        cursor = conn.cursor()
        try:
            cursor.execute(query, params)
            if fetch:
                result = cursor.fetchall()
                conn.close()
                return result
            conn.commit()
            last_id = cursor.lastrowid
            conn.close()
            return last_id
        except Exception as e:
            print(f"Query Error: {e}")
            conn.close()
            return None

class UpdateCaseDialog(QDialog):
    def __init__(self, current_status, current_severity, current_comment):
        super().__init__()
        self.setWindowTitle("Update Case Status")
        self.setFixedSize(400, 300)
        self.setStyleSheet(DARK_STYLESHEET) # Re-use your dark theme

        layout = QVBoxLayout()
        form_layout = QFormLayout()

        # --- Status Dropdown ---
        self.status_combo = QComboBox()
        # These must match your MySQL ENUM definition exactly
        self.status_combo.addItems(["OPEN", "INVESTIGATING", "CLOSED", "FALSE_POSITIVE"])
        self.status_combo.setCurrentText(current_status) # Set to current value
        
        # --- Severity Dropdown ---
        self.severity_combo = QComboBox()
        # These must match your MySQL ENUM definition exactly
        self.severity_combo.addItems(["LOW", "MEDIUM", "HIGH", "CRITICAL"])
        self.severity_combo.setCurrentText(current_severity) # Set to current value

        # --- Comments Field ---
        self.comment_input = QLineEdit()
        self.comment_input.setText(current_comment)

        form_layout.addRow("Case Status:", self.status_combo)
        form_layout.addRow("Severity Level:", self.severity_combo)
        form_layout.addRow("Comments:", self.comment_input)
        
        layout.addLayout(form_layout)

        # --- Buttons ---
        btn_box = QHBoxLayout()
        save_btn = QPushButton("Save Changes")
        save_btn.setObjectName("SuccessBtn") # Use your green styling
        save_btn.clicked.connect(self.accept)
        
        cancel_btn = QPushButton("Cancel")
        cancel_btn.setObjectName("DangerBtn")
        cancel_btn.clicked.connect(self.reject)

        btn_box.addWidget(save_btn)
        btn_box.addWidget(cancel_btn)
        layout.addLayout(btn_box)

        self.setLayout(layout)

    def get_data(self):
        return (
            self.status_combo.currentText(),
            self.severity_combo.currentText(),
            self.comment_input.text()
        )

# --- LOGIN WINDOW ---
class LoginWindow(QDialog):
    def __init__(self, db_manager):
        super().__init__()
        self.db = db_manager
        self.user_data = None
        self.setWindowTitle("SOC-Sentinel Login")
        self.setFixedSize(400, 250)
        self.setStyleSheet(DARK_STYLESHEET)
        
        layout = QVBoxLayout()
        layout.setSpacing(15)
        layout.setContentsMargins(40, 40, 40, 40)
        
        title = QLabel("SOC-Sentinel")
        title.setFont(QFont("Segoe UI", 24, QFont.Weight.Bold))
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setStyleSheet("color: #007acc;") 
        layout.addWidget(title)
        
        form_layout = QFormLayout()
        form_layout.setSpacing(10)
        
        self.user_input = QLineEdit()
        self.user_input.setPlaceholderText("Enter Username")
        
        self.pass_input = QLineEdit()
        self.pass_input.setPlaceholderText("Enter Password")
        self.pass_input.setEchoMode(QLineEdit.EchoMode.Password)
        
        form_layout.addRow("Username:", self.user_input)
        form_layout.addRow("Password:", self.pass_input)
        layout.addLayout(form_layout)
        
        login_btn = QPushButton("Login Securely")
        login_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        login_btn.clicked.connect(self.handle_login)
        layout.addWidget(login_btn)
        
        self.setLayout(layout)

    def handle_login(self):
        username = self.user_input.text()
        password = self.pass_input.text()
        
        query = "SELECT user_id, username, is_Admin FROM Users WHERE username=%s AND password_of_user=%s"
        result = self.db.query_sql(query, (username, password), fetch=True)
        
        if result:
            self.user_data = {"id": result[0][0], "name": result[0][1], "is_admin": result[0][2]}
            self.accept()
        else:
            QMessageBox.warning(self, "Access Denied", "Invalid Credentials")

# --- MAIN DASHBOARD ---
class MainWindow(QMainWindow):
    def __init__(self, user_data, db_manager):
        super().__init__()
        self.user = user_data
        self.db = db_manager
        self.logout_requested = False
        
        self.setWindowTitle(f"SOC-Sentinel Dashboard | User: {self.user['name'].upper()}")
        self.setGeometry(100, 100, 1280, 720)
        self.setStyleSheet(DARK_STYLESHEET)
        
        # Central Widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        
        # Header
        header = QHBoxLayout()
        role_text = "ADMINISTRATOR" if self.user['is_admin'] else "TIER-1 ANALYST"
        role_color = "#d83b01" if self.user['is_admin'] else "#007acc"
        
        lbl_role = QLabel(f"ROLE: {role_text}")
        lbl_role.setStyleSheet(f"color: {role_color}; font-weight: bold; font-size: 16px;")
        header.addWidget(lbl_role)
        
        header.addStretch()
        
        btn_logout = QPushButton("Logout")
        btn_logout.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_logout.clicked.connect(self.handle_logout)
        header.addWidget(btn_logout)
        main_layout.addLayout(header)
        
        # Tabs
        self.tabs = QTabWidget()
        main_layout.addWidget(self.tabs)
        
        # --- TAB 1: ANALYST VIEWS ---
        if not self.user['is_admin']:
            self.triage_tab = QWidget()
            self.setup_triage_tab()
            self.tabs.addTab(self.triage_tab, "Inbox (Triage)")
            
            self.cases_tab = QWidget()
            self.setup_my_cases_tab()
            self.tabs.addTab(self.cases_tab, "My Active Cases")

            self.closed_tab = QWidget()
            self.setup_closed_cases_tab()
            self.tabs.addTab(self.closed_tab, "Closed Cases")
        
        # --- TAB 2: ADMIN PANEL ---
        if self.user['is_admin']:
            self.admin_tab = QWidget()
            self.setup_admin_tab()
            self.tabs.addTab(self.admin_tab, "屏 Admin Panel")

        # --- Initial Check for New Logs on Startup ---
        self.run_ingestor_if_needed()

        # Timer to auto-refresh Triage every 10 seconds
        self.timer = QTimer()
        self.timer.timeout.connect(self.refresh_data)
        self.timer.start(10000)

    # -------------------------------------------------------------------------
    # AUTOMATION: HASHING & INGESTION
    # -------------------------------------------------------------------------
    def get_file_hash(self, filepath):
        """Calculates MD5 hash of a file to detect changes."""
        if not os.path.exists(filepath):
            return None
        hasher = hashlib.md5()
        try:
            with open(filepath, 'rb') as f:
                # Read in chunks to avoid memory issues with large files
                buf = f.read(65536)
                while len(buf) > 0:
                    hasher.update(buf)
                    buf = f.read(65536)
            return hasher.hexdigest()
        except Exception as e:
            print(f"Hashing Error: {e}")
            return None
    
    def log_history(self, case_id, change_type, old_val, new_val):
        """Helper to insert records into Case_History"""
        try:
            query = """
                INSERT INTO Case_History (case_id, user_id, change_type, old_value, new_value)
                VALUES (%s, %s, %s, %s, %s)
            """
            # We use self.user['id'] to track WHO made the change
            self.db.query_sql(query, (case_id, self.user['id'], change_type, old_val, new_val))
        except Exception as e:
            print(f"[-] Failed to log history: {e}")


    def setup_closed_cases_tab(self):
        layout = QVBoxLayout(self.closed_tab)
        
        # LABEL ONLY - No buttons!
        info_label = QLabel("Archived Cases (Read-Only)")
        info_label.setStyleSheet("color: #888; font-style: italic;")
        layout.addWidget(info_label)
        
        self.closed_table = QTableWidget()
        self.closed_table.setColumnCount(5)
        self.closed_table.setHorizontalHeaderLabels(["ID", "Status", "Severity", "Victim IP", "Final Comments"])
        self.closed_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.closed_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.closed_table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        
        # OPTIONAL: Make rows strictly non-editable (though QTableWidget is usually manual anyway)
        self.closed_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        
        layout.addWidget(self.closed_table)
        
        self.refresh_closed_cases()

    def refresh_closed_cases(self):
        self.closed_table.setRowCount(0)
        # QUERY: Only fetch 'CLOSED' status
        query = """
            SELECT c.case_id, c.status, c.severity, c.src_ip, c.comments 
            FROM Cases c 
            JOIN Case_Assignments ca ON c.case_id = ca.case_id 
            WHERE ca.user_id = %s AND c.status = 'CLOSED'
        """
        rows = self.db.query_sql(query, (self.user['id'],), fetch=True)
        if not rows: return
        for row_idx, row in enumerate(rows):
            self.closed_table.insertRow(row_idx)
            for col_idx, item in enumerate(row):
                # Add item to table
                item_widget = QTableWidgetItem(str(item))
                # Optional: Grey out text to indicate it's closed
                item_widget.setForeground(Qt.GlobalColor.gray)
                self.closed_table.setItem(row_idx, col_idx, item_widget)

    def run_ingestor_if_needed(self):
        """Checks if eve.json has changed. If yes, runs Ingestor.py."""
        print("[*] Checking for new logs in eve.json...")
        
        current_hash = self.get_file_hash(LOG_FILE_PATH)
        if not current_hash:
            # If file doesn't exist or permissions fail
            return

        stored_hash = ""
        # Read the stored hash if it exists
        if os.path.exists(HASH_FILE_PATH):
            with open(HASH_FILE_PATH, 'r') as f:
                stored_hash = f.read().strip()
        
        # Compare
        if current_hash != stored_hash:
            print("[!] Change detected (or First Run)! Running Ingestor...")
            
            # Show Wait Cursor
            QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)
            
            try:
                # Use sys.executable to ensure we use the venv python
                result = subprocess.run([sys.executable, INGESTOR_SCRIPT], capture_output=True, text=True)
                
                if result.returncode == 0:
                    print("[+] Ingestion Successful.")
                    print(result.stdout) 
                    
                    # Update the hash file with the NEW hash (likely of the empty file now)
                    new_hash = self.get_file_hash(LOG_FILE_PATH)
                    if new_hash:
                        with open(HASH_FILE_PATH, 'w') as f:
                            f.write(new_hash)
                else:
                    print("[-] Ingestion Script Failed:")
                    print(result.stderr)
                    
            except Exception as e:
                print(f"[-] Error running ingestor: {e}")
            finally:
                QApplication.restoreOverrideCursor()
        else:
            print("[*] No changes detected. Skipping ingestion.")

    def handle_logout(self):
        self.logout_requested = True
        self.close()

    # -------------------------------------------------------------------------
    # ANALYST: TRIAGE LOGIC
    # -------------------------------------------------------------------------
    def setup_triage_tab(self):
        layout = QVBoxLayout(self.triage_tab)
        
        # Controls
        controls = QHBoxLayout()
        btn_refresh = QPushButton("Refresh Inbox")
        btn_refresh.clicked.connect(self.refresh_triage) # Triggers hash check
        controls.addWidget(btn_refresh)
        
        btn_create = QPushButton("Promote to Case")
        btn_create.setObjectName("SuccessBtn")
        btn_create.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_create.clicked.connect(self.promote_to_case)
        controls.addWidget(btn_create)
        controls.addStretch()
        layout.addLayout(controls)
        
        # Table
        self.triage_table = QTableWidget()
        self.triage_table.setColumnCount(5)
        self.triage_table.setHorizontalHeaderLabels(["MongoID", "Timestamp", "Severity", "Source IP", "Alert Signature"])
        self.triage_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.triage_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.triage_table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        layout.addWidget(self.triage_table)
        
        self.refresh_triage()

    def refresh_triage(self):
        # Check for new logs before refreshing table
        self.run_ingestor_if_needed()
        
        self.triage_table.setRowCount(0)
        logs = self.db.mongo_col.find({"triage_status": "Unassigned"}).limit(50)
        
        for row_idx, log in enumerate(logs):
            self.triage_table.insertRow(row_idx)
            alert = log.get('alert', {})
            items = [str(log['_id']), log.get('timestamp', 'N/A'), str(alert.get('severity', 'N/A')),
                     log.get('src_ip', 'N/A'), alert.get('signature', 'Unknown')]
            for col_idx, text in enumerate(items):
                self.triage_table.setItem(row_idx, col_idx, QTableWidgetItem(text))

    def promote_to_case(self):
        # 1. Safety Check
        self.run_ingestor_if_needed()

        # 2. Get Selected Log
        selected = self.triage_table.currentRow()
        if selected < 0:
            QMessageBox.warning(self, "Warning", "Please select a log to promote.")
            return
            
        mongo_id = self.triage_table.item(selected, 0).text()
        log_data = self.db.mongo_col.find_one({"_id": ObjectId(mongo_id)})
        if not log_data: return
        
        # 3. Extract Data
        alert = log_data.get("alert", {})
        http = log_data.get("http", {})
        files = log_data.get("files", [])
        flow = log_data.get("flow", {}) 
        
        src_ip = log_data.get("src_ip", "0.0.0.0")
        dest_ip = log_data.get("dest_ip", "0.0.0.0")
        src_port = log_data.get("src_port", 0)
        dest_port = log_data.get("dest_port", 0)
        flow_id = log_data.get("flow_id", None)
        proto = log_data.get("proto", "TCP")
        alert_name = alert.get("signature", "Unknown Alert")

        # --- FIX 1: BETTER TIMESTAMP CLEANING ---
        # Suricata logs often look like "2025-12-14T14:12:43.084+0000"
        # We split by '+' to remove the timezone, then replace T with space.
        raw_ts = log_data.get("timestamp", "")
        ts_clean = raw_ts.split("+")[0].replace("T", " ")

        # 4. INSERT INTO 'CASES'
        case_query = """
            INSERT INTO Cases (status, severity, comments, flow_start_time, src_ip, dest_ip, src_port, dest_port, flow_id, proto) 
            VALUES ('OPEN', 'HIGH', %s, NOW(), %s, %s, %s, %s, %s, %s)
        """
        case_id = self.db.query_sql(case_query, (
            f"Triggered by: {alert_name}", src_ip, dest_ip, src_port, dest_port, flow_id, proto
        ))
        
        if not case_id:
            QMessageBox.critical(self, "Error", "Failed to create Case in SQL. Check console.")
            return

        # 5. Assign Analyst & Log History
        self.db.query_sql("INSERT INTO Case_Assignments (case_id, user_id) VALUES (%s, %s)", (case_id, self.user['id']))
        
        # --- FIX 2: MOVED HISTORY LOGGING HERE ---
        # This ensures the history is written even if the raw log detail insert fails later.
        self.log_history(case_id, "CASE CREATED", "N/A", f"Created by {self.user['name']}")

        # 6. INSERT INTO 'All_Log_Details'
        log_query = """
            INSERT INTO All_Log_Details 
            (case_id, timestamp, event_type, interface_in, traffic_direction, 
             pkts_toserver, pkts_toclient, bytes_toserver, bytes_toclient, payload_printable)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """
        
        direction = "inbound" if dest_ip.startswith("192.168") else "outbound"
        
        # --- FIX 3: ADDED ERROR CHECKING ---
        # We check if log_id is None and print why.
        log_id = self.db.query_sql(log_query, (
            case_id, 
            ts_clean, 
            log_data.get("event_type"), 
            log_data.get("in_iface"), 
            direction,
            flow.get("pkts_toserver", 0),
            flow.get("pkts_toclient", 0),
            flow.get("bytes_toserver", 0),
            flow.get("bytes_toclient", 0),
            log_data.get("payload_printable", "")
        ))

        if not log_id:
            print(f"[-] ERROR: Failed to insert into All_Log_Details. Timestamp used: {ts_clean}")
            # We don't return here, we let the UI update, but the details tab will be empty.

        # 7. Insert Sub-Details
        if log_id:
            if alert:
                ctx_query = "INSERT INTO Detail_Alert_Context (log_id, signature_id, gid, action_taken) VALUES (%s, %s, %s, %s)"
                self.db.query_sql(ctx_query, (log_id, alert.get("signature_id"), alert.get("gid"), alert.get("action")))

            if http:
                http_query = """
                    INSERT INTO Detail_HTTP_Transactions 
                    (log_id, hostname, url, http_user_agent, http_content_type, http_method, http_protocol, http_status, response_length, http_response_body)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """
                self.db.query_sql(http_query, (
                    log_id, 
                    http.get("hostname"), 
                    http.get("url"), 
                    http.get("http_user_agent"), 
                    http.get("content_type"),
                    http.get("http_method"), 
                    http.get("protocol"), 
                    http.get("status"), 
                    http.get("length"), 
                    str(http.get("response_body", ""))
                ))

            if files:
                file_query = "INSERT INTO Detail_File_Artifacts (log_id, filename, state, is_stored, size_bytes, tx_id) VALUES (%s, %s, %s, %s, %s, %s)"
                for f in files:
                    self.db.query_sql(file_query, (
                        log_id, 
                        f.get("filename"), 
                        f.get("state"), 
                        f.get("stored", False), 
                        f.get("size", 0), 
                        f.get("tx_id", 0)
                    ))
            
        # 8. Update Mongo Status
        self.db.mongo_col.update_one({"_id": ObjectId(mongo_id)}, {"$set": {"triage_status": "Assigned", "case_id": case_id}})
        
        QMessageBox.information(self, "Success", f"Case #{case_id} Created!")
        self.refresh_triage()
        if hasattr(self, 'cases_table'): self.refresh_my_cases()

    # -------------------------------------------------------------------------
    # ANALYST: MY CASES
    # -------------------------------------------------------------------------
    def setup_my_cases_tab(self):
        layout = QVBoxLayout(self.cases_tab)
        
        btn_update = QPushButton("Update Case Status and Details")
        btn_update.clicked.connect(self.handle_case_update)
        layout.addWidget(btn_update)
        
        self.cases_table = QTableWidget()
        self.cases_table.setColumnCount(5)
        self.cases_table.setHorizontalHeaderLabels(["ID", "Status", "Severity", "Victim IP", "Comments"])
        self.cases_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.cases_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.cases_table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        layout.addWidget(self.cases_table)
        
        self.refresh_my_cases()

    def refresh_my_cases(self):
        self.cases_table.setRowCount(0)
        query = """
            SELECT c.case_id, c.status, c.severity, c.src_ip, c.comments 
            FROM Cases c 
            JOIN Case_Assignments ca ON c.case_id = ca.case_id 
            WHERE ca.user_id = %s AND c.status != 'CLOSED'
        """
        rows = self.db.query_sql(query, (self.user['id'],), fetch=True)
        if not rows: return
        for row_idx, row in enumerate(rows):
            self.cases_table.insertRow(row_idx)
            for col_idx, item in enumerate(row):
                self.cases_table.setItem(row_idx, col_idx, QTableWidgetItem(str(item)))


    def handle_case_update(self):
        row = self.cases_table.currentRow()
        if row < 0:
            QMessageBox.warning(self, "Selection Missing", "Please select a case to update.")
            return

        # 1. Capture OLD Data (Before the change)
        case_id = self.cases_table.item(row, 0).text()
        curr_status = self.cases_table.item(row, 1).text()
        curr_severity = self.cases_table.item(row, 2).text()
        curr_comment = self.cases_table.item(row, 4).text()

        # 2. Get NEW Data from Dialog
        dialog = UpdateCaseDialog(curr_status, curr_severity, curr_comment)
        
        if dialog.exec() == QDialog.DialogCode.Accepted:
            new_status, new_severity, new_comment = dialog.get_data()
            
            # 3. DETECT & LOG CHANGES
            # Did Status change? (e.g., OPEN -> CLOSED)
            if curr_status != new_status:
                self.log_history(case_id, "STATUS UPDATE", curr_status, new_status)
                
            # Did Severity change?
            if curr_severity != new_severity:
                self.log_history(case_id, "SEVERITY UPDATE", curr_severity, new_severity)

            # Did Comment change?
            if curr_comment != new_comment:
                self.log_history(case_id, "COMMENT UPDATE", curr_comment, new_comment)

            # 4. Perform the actual Update
            try:
                query = "UPDATE Cases SET status = %s, severity = %s, comments = %s WHERE case_id = %s"
                self.db.query_sql(query, (new_status, new_severity, new_comment, case_id))
                
                QMessageBox.information(self, "Success", "Case updated and changes logged.")
                self.refresh_my_cases()
                
            except Exception as e:
                QMessageBox.critical(self, "Update Error", str(e))

    # -------------------------------------------------------------------------
    # ADMIN PANEL
    # -------------------------------------------------------------------------
    def setup_admin_tab(self):
        layout = QVBoxLayout(self.admin_tab)
        
        # --- Assignment Section ---
        assign_frame = QFrame()
        assign_frame.setStyleSheet("background-color: #2d2d30; border-radius: 5px; padding: 10px;")
        assign_layout = QHBoxLayout(assign_frame)
        
        lbl_assign = QLabel("Team Management:")
        lbl_assign.setStyleSheet("border: none; margin-right: 10px;")
        
        self.combo_analysts = QComboBox()
        self.combo_analysts.setMinimumWidth(200)
        self.refresh_analyst_list() 
        
        btn_assign = QPushButton("Add Analyst")
        btn_assign.setObjectName("SuccessBtn")
        btn_assign.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_assign.clicked.connect(self.admin_assign_case)
        
        btn_remove_analyst = QPushButton("Remove Analyst")
        btn_remove_analyst.setObjectName("WarningBtn")
        btn_remove_analyst.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_remove_analyst.clicked.connect(self.admin_remove_analyst)

        assign_layout.addWidget(lbl_assign)
        assign_layout.addWidget(self.combo_analysts)
        assign_layout.addWidget(btn_assign)
        assign_layout.addWidget(btn_remove_analyst)
        assign_layout.addStretch()
        
        # --- Delete Section ---
        btn_delete = QPushButton("DELETE SELECTED CASE")
        btn_delete.setObjectName("DangerBtn")
        btn_delete.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_delete.clicked.connect(self.admin_delete_case)
        
        layout.addWidget(assign_frame)
        layout.addWidget(btn_delete)
        
        # --- Table ---
        self.admin_table = QTableWidget()
        self.admin_table.setColumnCount(6)
        self.admin_table.setHorizontalHeaderLabels(["ID", "Status", "Severity", "Victim IP", "Assigned Analysts", "Comments"])
        self.admin_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.admin_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.admin_table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        layout.addWidget(self.admin_table)
        
        self.refresh_admin_cases()

    def refresh_analyst_list(self):
        self.combo_analysts.clear()
        query = "SELECT user_id, username FROM Users WHERE is_Admin = 0"
        analysts = self.db.query_sql(query, fetch=True)
        if analysts:
            for uid, name in analysts:
                self.combo_analysts.addItem(f"{name} (ID: {uid})", uid)

    def admin_assign_case(self):
        row = self.admin_table.currentRow()
        if row < 0:
            QMessageBox.warning(self, "Selection Missing", "Please select a case from the table first.")
            return

        case_id = self.admin_table.item(row, 0).text()
        analyst_idx = self.combo_analysts.currentIndex()
        if analyst_idx == -1: return
        target_user_id = self.combo_analysts.currentData()
        
        try:
            self.db.query_sql("INSERT IGNORE INTO Case_Assignments (case_id, user_id) VALUES (%s, %s)", (case_id, target_user_id))
            QMessageBox.information(self, "Success", f"Analyst added to Case #{case_id}")
            self.refresh_admin_cases()
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    def admin_remove_analyst(self):
        row = self.admin_table.currentRow()
        if row < 0:
            QMessageBox.warning(self, "Selection Missing", "Please select a case from the table first.")
            return

        case_id = self.admin_table.item(row, 0).text()

        query = "SELECT u.username, u.user_id FROM Users u JOIN Case_Assignments ca ON u.user_id = ca.user_id WHERE ca.case_id = %s"
        current_team = self.db.query_sql(query, (case_id,), fetch=True)
        
        if not current_team:
            QMessageBox.warning(self, "Error", "No analysts are currently assigned to this case.")
            return

        display_list = [f"{name} (ID: {uid})" for name, uid in current_team]
        selected_str, ok = QInputDialog.getItem(self, "Remove Analyst", f"Select Analyst to remove from Case #{case_id}:", display_list, 0, False)
        
        if ok and selected_str:
            target_user_id = selected_str.split("ID: ")[1].replace(")", "")
            try:
                self.db.query_sql("DELETE FROM Case_Assignments WHERE case_id=%s AND user_id=%s", (case_id, target_user_id))
                QMessageBox.information(self, "Success", f"Analyst removed from Case #{case_id}")
                self.refresh_admin_cases()
            except Exception as e:
                QMessageBox.critical(self, "Error", str(e))

    def refresh_admin_cases(self):
        self.admin_table.setRowCount(0)
        query = """
            SELECT 
                c.case_id, 
                c.status, 
                c.severity, 
                c.src_ip, 
                GROUP_CONCAT(u.username SEPARATOR ', ') AS analysts,
                c.comments 
            FROM Cases c
            LEFT JOIN Case_Assignments ca ON c.case_id = ca.case_id
            LEFT JOIN Users u ON ca.user_id = u.user_id
            GROUP BY c.case_id
        """
        rows = self.db.query_sql(query, fetch=True)
        if not rows: return
        for row_idx, row in enumerate(rows):
            self.admin_table.insertRow(row_idx)
            for col_idx, item in enumerate(row):
                val = str(item) if item is not None else ""
                self.admin_table.setItem(row_idx, col_idx, QTableWidgetItem(val))

    def admin_delete_case(self):
        row = self.admin_table.currentRow()
        if row < 0: 
            QMessageBox.warning(self, "Selection Missing", "Please select a case to delete.")
            return
        case_id = self.admin_table.item(row, 0).text()
        reply = QMessageBox.question(self, 'Confirm Delete', f"Delete Case #{case_id}?", QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes:
            self.db.query_sql("DELETE FROM Cases WHERE case_id = %s", (case_id,))
            self.refresh_admin_cases()

    def refresh_data(self):
        # Refresh Logic triggers ingestion check
        self.run_ingestor_if_needed()
        if hasattr(self, 'triage_table'): self.refresh_triage()
        if hasattr(self, 'cases_table'): self.refresh_my_cases() 
        if hasattr(self, 'closed_table'): self.refresh_closed_cases()
        if hasattr(self, 'admin_table'): self.refresh_admin_cases()

# --- APP EXECUTION ---
if __name__ == "__main__":
    app = QApplication(sys.argv)
    db_manager = DbManager()
    
    while True:
        login = LoginWindow(db_manager)
        if login.exec() == QDialog.DialogCode.Accepted:
            window = MainWindow(login.user_data, db_manager)
            window.show()
            app.exec()
            if not window.logout_requested:
                break
        else:
            break
            
    sys.exit()