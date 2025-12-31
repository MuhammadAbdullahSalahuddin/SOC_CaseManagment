import json
import mysql.connector
from pymongo import MongoClient
import os

# --- 1. CONFIGURATION ---
DB_CONFIG = {
    "host": "localhost",
    "user": "root",
    "password": "thebe", 
    "database": "suricata_db"
}

LOG_FILE = "/var/log/suricata/eve.json"

# --- 2. DATABASE CONNECTIONS ---
def get_db_connections():
    try:
        # 1. Connect to MySQL (Rules Catalog)
        sql_db = mysql.connector.connect(**DB_CONFIG)
        cursor = sql_db.cursor()
        
        # 2. Connect to MongoDB (Data Inbox) - AUTHENTICATED
        mongo_uri = "mongodb://admin:thebe@localhost:27017/?authSource=admin"
        mongo_client = MongoClient(mongo_uri)
        
        # 3. Use the correct database
        mongo_db = mongo_client["suricata_db"] 
        evidence_col = mongo_db["raw_logs"]
        
        return sql_db, cursor, evidence_col
        
    except Exception as e:
        print(f"[-] Database Connection Error: {e}")
        return None, None, None

# --- 3. MAIN INGESTION LOGIC ---
def process_logs(filename):
    print(f"[*] Starting Ingestion of {filename}...")
    
    # Check if file exists first
    if not os.path.exists(filename):
        print(f"[-] Error: File {filename} not found.")
        return

    sql_db, cursor, evidence_col = get_db_connections()
    if not sql_db: 
        return

    count = 0
    new_rules = 0

    try:
        # READ AND PROCESS MODE
        with open(filename, 'r') as file:
            for line in file:
                if not line.strip(): continue
                
                try:
                    data = json.loads(line)
                    
                    # Filter: Only process Alerts
                    if data.get("event_type") != "alert": continue 

                    # --- TASK A: MYSQL RULES CATALOG ---
                    alert = data.get("alert", {})
                    cursor.execute("""
                        INSERT IGNORE INTO Reference_Rules_Catalog 
                        (signature_id, gid, signature_name, category, severity, revision)
                        VALUES (%s, %s, %s, %s, %s, %s)
                    """, (
                        alert.get("signature_id"), 
                        alert.get("gid"), 
                        alert.get("signature"),
                        alert.get("category"), 
                        alert.get("severity"), 
                        alert.get("rev")
                    ))
                    
                    if cursor.rowcount > 0:
                        new_rules += 1

                    # --- TASK B: MONGODB INBOX ---
                    data["triage_status"] = "Unassigned"
                    data["case_id"] = None
                    
                    # Insert into MongoDB
                    evidence_col.insert_one(data)
                    
                    # Commit MySQL changes
                    sql_db.commit()
                    count += 1

                except json.JSONDecodeError:
                    continue 
                except Exception as e:
                    # If MongoDB schema validation fails, print but don't crash
                    print(f"[-] Error processing line: {e}")
                    continue
        
        # --- NEW LOGIC: CLEAR THE FILE ---
        # We assume if we reached this point, the file was read successfully.
        # Now we reopen it in 'w' mode to wipe it clean.
        try:
            with open(filename, 'w') as f:
                f.truncate(0)
            print(f"[*] Successfully emptied {filename}.")
        except PermissionError:
            print(f"[-] PERMISSION DENIED: Could not clear {filename}. Run as sudo.")
        except Exception as e:
            print(f"[-] Error clearing log file: {e}")

    except Exception as e:
        print(f"[-] Critical Error during processing: {e}")
    finally:
        if sql_db.is_connected():
            cursor.close()
            sql_db.close()
            print("[-] Database connections closed.")

    print(f"\n[*] INGESTION COMPLETE.")
    print(f"    - Total Alerts sent to MongoDB Inbox: {count}")
    print(f"    - New Rules added to SQL Catalog: {new_rules}")

# --- 4. EXECUTION ---
if __name__ == "__main__":
    process_logs(LOG_FILE)