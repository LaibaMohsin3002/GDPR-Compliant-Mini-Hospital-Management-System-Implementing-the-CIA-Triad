"""
Streamlit Hospital Management Dashboard
- SQLite DB (hospital.db)
- RBAC: admin / doctor / receptionist
- Confidentiality: masking + optional reversible Fernet encryption
- Integrity: action logs (user_id, role, action, timestamp, details)
- Availability: try/except DB ops, CSV export, uptime
"""

import streamlit as st
import sqlite3
import hashlib
import os
import time
import datetime
import pandas as pd
from cryptography.fernet import Fernet
import altair as alt


# -------------------------
# Configuration / Constants
# -------------------------
DB_PATH = "hospital.db"
FERNET_KEY_PATH = "fernet.key"
APP_START = time.time()

# -------------------------
# Utility: Fernet key init
# -------------------------
def get_fernet():
    try:
        if os.path.exists(FERNET_KEY_PATH):
            with open(FERNET_KEY_PATH, "rb") as f:
                key = f.read()
        else:
            key = Fernet.generate_key()
            with open(FERNET_KEY_PATH, "wb") as f:
                f.write(key)
        return Fernet(key)
    except Exception as e:
        # If cryptography fails, return None (we still proceed with masking only)
        st.error("Fernet unavailable: " + str(e))
        return None

FERNET = get_fernet()

# -------------------------
# Database helpers
# -------------------------
def get_conn():
    return sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES|sqlite3.PARSE_COLNAMES)

def init_db():
    conn = get_conn()
    c = conn.cursor()
    # users table
    c.execute("""
    CREATE TABLE IF NOT EXISTS users (
        user_id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password_hash TEXT,
        role TEXT
    )""")
    # patients table
    c.execute("""
    CREATE TABLE IF NOT EXISTS patients (
        patient_id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        contact TEXT,
        diagnosis TEXT,
        anonymized_name TEXT,
        anonymized_contact TEXT,
        encrypted_name BLOB,
        encrypted_contact BLOB,
        date_added TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )""")
    # logs table
    c.execute("""
    CREATE TABLE IF NOT EXISTS logs (
        log_id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        username TEXT,
        role TEXT,
        action TEXT,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        details TEXT
    )""")
    # settings table for last_sync
    c.execute("""
    CREATE TABLE IF NOT EXISTS settings (
        k TEXT PRIMARY KEY,
        v TEXT
    )""")
        # GDPR consent table
    c.execute("""
    CREATE TABLE IF NOT EXISTS consent (
        consent_id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        consent_text TEXT,
        accepted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    # Add data retention column if missing
    c.execute("PRAGMA table_info(patients)")
    cols = [col[1] for col in c.fetchall()]
    if "retention_until" not in cols:
        c.execute("ALTER TABLE patients ADD COLUMN retention_until TIMESTAMP")

    # seed users if not exist
    users = [
        ("admin", "admin123", "admin"),
        ("drbob", "doc123", "doctor"),
        ("alice_recep", "rec123", "receptionist")
    ]
    for uname, pwd, role in users:
        # store salted hash
        pwd_hash = hashlib.sha256((uname + pwd).encode()).hexdigest()
        try:
            c.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)", (uname, pwd_hash, role))
        except sqlite3.IntegrityError:
            pass
    # set last_sync if missing
    c.execute("INSERT OR IGNORE INTO settings (k, v) VALUES ('last_sync', ?)", (datetime.datetime.utcnow().isoformat(),))
    conn.commit()
    conn.close()

# Initialize DB at import
init_db()

# -------------------------
# Security / Masking Utils
# -------------------------
def mask_contact(contact: str) -> str:
    # simple mask: keep last 4 digits, replace others with X
    digits = ''.join(filter(str.isdigit, contact))
    if len(digits) >= 4:
        return 'XXX-XXX-' + digits[-4:]
    else:
        return 'XXX-XXX-XXXX'

def generate_anon_name(patient_id: int) -> str:
    # deterministic pseudo-anon label
    return f"ANON_{1000 + patient_id}"

def encrypt_value(value: str) -> bytes:
    if FERNET:
        return FERNET.encrypt(value.encode())
    else:
        return None

def decrypt_value(token: bytes) -> str:
    if FERNET and token:
        try:
            return FERNET.decrypt(token).decode()
        except Exception:
            return "[decrypt-failed]"
    return None

# -------------------------
# Logging helper
# -------------------------
def log_action(user_id, username, role, action, details=""):
    try:
        conn = get_conn()
        c = conn.cursor()
        c.execute("INSERT INTO logs (user_id, username, role, action, details) VALUES (?, ?, ?, ?, ?)",
                  (user_id, username, role, action, details))
        # update last_sync
        c.execute("UPDATE settings SET v = ? WHERE k = 'last_sync'", (datetime.datetime.utcnow().isoformat(),))
        conn.commit()
    except Exception as e:
        st.error("Failed to write log: " + str(e))
    finally:
        conn.close()

# -------------------------
# Authentication
# -------------------------
def authenticate(username, password):
    try:
        conn = get_conn()
        c = conn.cursor()
        c.execute("SELECT user_id, password_hash, role FROM users WHERE username = ?", (username,))
        row = c.fetchone()
        conn.close()
        if not row:
            return None
        user_id, stored_hash, role = row
        provided_hash = hashlib.sha256((username + password).encode()).hexdigest()
        if provided_hash == stored_hash:
            return {"user_id": user_id, "username": username, "role": role}
        else:
            return None
    except Exception as e:
        st.error("Auth DB error: " + str(e))
        return None

# -------------------------
# UI Components
# -------------------------
# def login_ui():
#     st.title("Hospital Management — Login")
#     username = st.text_input("Username")
#     password = st.text_input("Password", type="password")
#     if st.button("Login"):
#         user = authenticate(username.strip(), password.strip())
#         if user:
#             st.success(f"Welcome {user['username']} ({user['role']})")
#             # set session state
#             st.session_state['user'] = user
#             log_action(user['user_id'], user['username'], user['role'], "login", "successful login")
#             st.experimental_rerun()
#         else:
#             st.warning("Invalid credentials")
#             # log failed attempt with role unknown
#             log_action(None, username, "unknown", "login_failed", "invalid credentials")

def login_ui():
    # GDPR consent banner
    consent_text = """By using this system you consent to the storage and processing of personal data under GDPR guidelines."""

    st.info(consent_text)

    if "consent_given" not in st.session_state:
        if st.button("Accept & Continue"):
            st.session_state["consent_given"] = True
            conn = get_conn()
            conn.execute("INSERT INTO consent (username, consent_text) VALUES (?, ?)", 
                         ("anonymous", consent_text))
            conn.commit()
            conn.close()
            st.experimental_rerun()
        return

    st.title("Hospital Management — Login")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    if st.button("Login"):
        user = authenticate(username.strip(), password.strip())
        if user:
            st.success(f"Welcome {user['username']} ({user['role']})")
            st.session_state['user'] = user
            log_action(user['user_id'], user['username'], user['role'], "login", "successful")
            st.experimental_rerun()
        else:
            st.warning("Invalid credentials")
            log_action(None, username, "unknown", "login_failed", "invalid credentials")


def show_footer():
    try:
        conn = get_conn()
        c = conn.cursor()
        c.execute("SELECT v FROM settings WHERE k = 'last_sync'")
        row = c.fetchone()
        conn.close()
        last_sync = row[0] if row else "unknown"
    except Exception:
        last_sync = "unknown"
    uptime_seconds = int(time.time() - APP_START)
    uptime = str(datetime.timedelta(seconds=uptime_seconds))
    st.sidebar.markdown("---")
    st.sidebar.write(f"**Uptime:** {uptime}")
    st.sidebar.write(f"**Last sync (UTC):** {last_sync}")

def activity_graph():
    conn = get_conn()
    df = pd.read_sql_query("""
        SELECT DATE(timestamp) as day, COUNT(*) as actions
        FROM logs
        GROUP BY DATE(timestamp)
        ORDER BY day
    """, conn)
    conn.close()

    if df.empty:
        st.info("No activity yet.")
        return

    chart = alt.Chart(df).mark_line(point=True).encode(
        x="day:T",
        y="actions:Q"
    ).properties(title="User Activity Per Day")

    st.altair_chart(chart, use_container_width=True)

# -------------------------
# Admin Controls
# -------------------------
def admin_view(user):
    st.header("Admin Dashboard")
    show_patients_table(user, show_raw=True)
    st.markdown("### Admin Actions")
    if st.button("Anonymize all patient records"):
        anonymize_all(user)
    if st.button("Encrypt all raw personal data (reversible - Fernet)"):
        encrypt_all(user)
    if st.button("Export patients CSV"):
        export_patients_csv()
    st.markdown("### Integrity Audit Log")
    show_logs_table()
    st.markdown("### GDPR — Data Retention")
    try:
        conn = get_conn()
        df = pd.read_sql_query("""
            SELECT patient_id, anonymized_name, retention_until 
            FROM patients 
            WHERE retention_until IS NOT NULL 
            ORDER BY retention_until ASC
            """, conn)
        conn.close()
        st.dataframe(df)
    except:
        st.warning("No retention data.")
    st.markdown("### Real-Time Activity Graph")
    activity_graph()
    
# -------------------------
# Doctor Controls
# -------------------------
def doctor_view(user):
    st.header("Doctor Dashboard")
    st.info("You see anonymized patient info only.")
    show_patients_table(user, show_raw=False)

# -------------------------
# Receptionist Controls
# -------------------------
def receptionist_view(user):
    st.header("Receptionist Dashboard")
    st.info("You can add/edit patient records but cannot view sensitive data.")
    show_add_patient_form(user)
    show_patients_table(user, show_raw=False, receptionist=True)

# -------------------------
# Patient operations
# -------------------------
def show_patients_table(user, show_raw=False, receptionist=False):
    try:
        conn = get_conn()
        df = pd.read_sql_query("SELECT patient_id, anonymized_name, anonymized_contact, diagnosis, date_added, name, contact FROM patients ORDER BY date_added DESC", conn)
        conn.close()
        if df.empty:
            st.write("No patients yet.")
            return
        # Prepare display based on role
        display_df = df.copy()
        if show_raw:
            # Admin: show raw but allow decrypt if encrypted
            def maybe_decrypt(row):
                try:
                    if row['name'] and row['name'].startswith("gAAAA"):  # Fernet token starts with gAAAA
                        dec = decrypt_value(row['name'].encode() if isinstance(row['name'], str) else row['name'])
                        return dec if dec else row['name']
                    return row['name']
                except Exception:
                    return row['name']
            # Note: This simplistic check handles bytes stored as TEXT by sqlite; depends on implementation.
            display_df['Raw name'] = display_df['name']
            display_df['Raw contact'] = display_df['contact']
            st.dataframe(display_df[['patient_id','Raw name','Raw contact','anonymized_name','anonymized_contact','diagnosis','date_added']])
        else:
            # Doctor or Receptionist: hide real names, show anonymized fields only
            cols = ['patient_id','anonymized_name','anonymized_contact','diagnosis','date_added']
            st.dataframe(display_df[cols])
            # Receptionist allowed to edit/add but not view sensitive fields
            if receptionist:
                st.markdown("**Edit patient record (by patient_id)**")
                pid = st.number_input("Patient ID to edit (leave 0 to skip)", min_value=0, value=0, step=1)
                if pid:
                    edit_patient_form(pid, user)
    except Exception as e:
        st.error("Failed to load patients: " + str(e))

def show_add_patient_form(user):
    st.markdown("### Add new patient")
    with st.form("add_patient"):
        name = st.text_input("Full name")
        contact = st.text_input("Contact")
        diagnosis = st.text_area("Diagnosis")
        submitted = st.form_submit_button("Add patient")
        if submitted:
            try:
                conn = get_conn()
                c = conn.cursor()
                # c.execute("INSERT INTO patients (name, contact, diagnosis) VALUES (?, ?, ?)", (name, contact, diagnosis))
                retention_days = 30  # default policy
                retention_until = datetime.datetime.utcnow() + datetime.timedelta(days=retention_days)
                c.execute("""INSERT INTO patients (name, contact, diagnosis, retention_until) VALUES (?, ?, ?, ?)""", (name, contact, diagnosis, retention_until))
                conn.commit()
                pid = c.lastrowid
                # Create anonymized values immediately
                anon_name = generate_anon_name(pid)
                anon_contact = mask_contact(contact)
                c.execute("UPDATE patients SET anonymized_name = ?, anonymized_contact = ? WHERE patient_id = ?", (anon_name, anon_contact, pid))
                conn.commit()
                conn.close()
                st.success(f"Patient added with id {pid}")
                log_action(user['user_id'], user['username'], user['role'], "add_patient", f"patient_id={pid}")
            except Exception as e:
                st.error("Add failed: " + str(e))
    
def edit_patient_form(pid, user):
    try:
        conn = get_conn()
        c = conn.cursor()
        c.execute("SELECT patient_id, anonymized_name, anonymized_contact, diagnosis FROM patients WHERE patient_id = ?", (pid,))
        row = c.fetchone()
        if not row:
            st.warning("Patient not found")
            return
        _, anon_name, anon_contact, diagnosis = row
        new_diagnosis = st.text_area("Diagnosis", value=diagnosis)
        if st.button("Save changes"):
            try:
                # validation: receptionist cannot edit anonymized_name/contact directly
                c.execute("UPDATE patients SET diagnosis = ? WHERE patient_id = ?", (new_diagnosis, pid))
                conn.commit()
                st.success("Updated")
                log_action(user['user_id'], user['username'], user['role'], "edit_patient", f"patient_id={pid}")
            except Exception as e:
                st.error("Edit failed: " + str(e))
        conn.close()
    except Exception as e:
        st.error("Edit form error: " + str(e))

# -------------------------
# Anonymize and Encryption Ops
# -------------------------
def anonymize_all(user):
    try:
        conn = get_conn()
        c = conn.cursor()
        c.execute("SELECT patient_id, contact FROM patients")
        rows = c.fetchall()
        for pid, contact in rows:
            anon_name = generate_anon_name(pid)
            anon_contact = mask_contact(contact if contact else "")
            c.execute("UPDATE patients SET anonymized_name = ?, anonymized_contact = ? WHERE patient_id = ?", (anon_name, anon_contact, pid))
        conn.commit()
        conn.close()
        st.success("All patient records anonymized (anonymized_name/anonymized_contact updated).")
        log_action(user['user_id'], user['username'], user['role'], "anonymize_all", f"anonymized {len(rows)} records")
    except Exception as e:
        st.error("Anonymization failed: " + str(e))

def encrypt_all(user):
    if not FERNET:
        st.warning("Fernet encryption not available on this system.")
        return
    try:
        conn = get_conn()
        c = conn.cursor()
        c.execute("SELECT patient_id, name, contact FROM patients")
        rows = c.fetchall()
        count = 0
        for pid, name, contact in rows:
            if name:
                enc_name = encrypt_value(name)
                enc_contact = encrypt_value(contact if contact else "")
                # store as bytes; sqlite may accept bytes
                c.execute("UPDATE patients SET encrypted_name = ?, encrypted_contact = ? WHERE patient_id = ?", (enc_name, enc_contact, pid))
                count += 1
        conn.commit()
        conn.close()
        st.success(f"Encrypted personal data for {count} patients (stored in encrypted_name/contact).")
        log_action(user['user_id'], user['username'], user['role'], "encrypt_all", f"encrypted {count} records")
    except Exception as e:
        st.error("Encryption failed: " + str(e))

# -------------------------
# Logs & Export
# -------------------------
def show_logs_table():
    try:
        conn = get_conn()
        df = pd.read_sql_query("SELECT log_id, user_id, username, role, action, timestamp, details FROM logs ORDER BY timestamp DESC LIMIT 500", conn)
        conn.close()
        if df.empty:
            st.write("No logs yet.")
            return
        st.dataframe(df)
        if st.button("Export logs CSV"):
            csv = df.to_csv(index=False).encode('utf-8')
            st.download_button("Download logs.csv", data=csv, file_name="logs.csv", mime="text/csv")
    except Exception as e:
        st.error("Failed to load logs: " + str(e))

def export_patients_csv():
    try:
        conn = get_conn()
        df = pd.read_sql_query("SELECT * FROM patients ORDER BY date_added DESC", conn)
        conn.close()
        x = df.to_csv(index=False).encode('utf-8')
        st.download_button("Download patients.csv", data=x, file_name="patients.csv", mime="text/csv")
    except Exception as e:
        st.error("Export failed: " + str(e))

def enforce_data_retention():
    try:
        conn = get_conn()
        c = conn.cursor()
        c.execute("DELETE FROM patients WHERE retention_until IS NOT NULL AND retention_until < CURRENT_TIMESTAMP")
        deleted = conn.total_changes
        conn.commit()
        conn.close()
        if deleted > 0:
            st.warning(f"GDPR: {deleted} expired records auto-deleted.")
    except Exception as e:
        st.error("Retention enforcement failed: " + str(e))

# -------------------------
# Main App Flow
# -------------------------
def main():
    st.set_page_config(page_title="Mini Hospital — GDPR demo", layout="wide")
    
    show_footer()
    if 'user' not in st.session_state:
        login_ui()
        return
    
    enforce_data_retention()

    user = st.session_state['user']
    # Topbar info and logout
    cols = st.columns([1,4,1])
    cols[0].write("")
    cols[1].markdown(f"### Logged in as **{user['username']}** — role: **{user['role']}**")
    if cols[2].button("Logout"):
        log_action(user.get('user_id'), user.get('username'), user.get('role'), "logout", "user logged out")
        del st.session_state['user']
        st.experimental_rerun()

    # Role-based pages
    role = user['role']
    if role == "admin":
        admin_view(user)
    elif role == "doctor":
        doctor_view(user)
    elif role == "receptionist":
        receptionist_view(user)
    else:
        st.warning("Unknown role. Contact admin.")
        log_action(user.get('user_id'), user.get('username'), role, "unknown_role_access")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        st.error("Application error: " + str(e))
