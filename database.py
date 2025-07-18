import sqlite3
from werkzeug.security import generate_password_hash
import os

DATABASE = 'database.db'

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row # This allows us to access columns by name
    return conn

def init_db()
    if os.path.exists(DATABASE)
        os.remove(DATABASE) # Remove existing db for fresh start in development
    
    conn = get_db()
    cursor = conn.cursor()

    # Create users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'staff', -- 'staff' or 'admin'
            department TEXT,
            full_name TEXT
        );
    ''')

    # Create departments table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS departments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL
        );
    ''')

    # Create issue_types table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS issue_types (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL
        );
    ''')

    # Create tickets table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS tickets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            requester_id INTEGER NOT NULL,
            department_id INTEGER,
            issue_type_id INTEGER,
            subject TEXT NOT NULL,
            description TEXT,
            urgency TEXT NOT NULL DEFAULT 'Medium', -- Low, Medium, High, Critical
            status TEXT NOT NULL DEFAULT 'Open', -- Open, In Progress, Resolved, Closed
            assigned_to_id INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            resolution_notes TEXT,
            FOREIGN KEY (requester_id) REFERENCES users(id),
            FOREIGN KEY (department_id) REFERENCES departments(id),
            FOREIGN KEY (issue_type_id) REFERENCES issue_types(id),
            FOREIGN KEY (assigned_to_id) REFERENCES users(id)
        );
    ''')

    # Create ticket_comments table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS ticket_comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ticket_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            comment TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (ticket_id) REFERENCES tickets(id),
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
    ''')

    # Insert initial departments
    departments = [
        (Radiology,), (Radiotherapy,), (Outpatient Services,),
        (Inpatient Services,), (IT Department,), (Administration,)
    ]
    cursor.executemany(INSERT OR IGNORE INTO departments (name) VALUES (), departments)

    # Insert initial issue types
    issue_types = [
        (Network Issue,), (Printer Issue,), (EMR Issue,),
        (EMR Service UploadUpdate,), (EMR New User Creation,),
        (New Email in AD Creation,), (Hardware Issue,), (Software Issue,)
    ]
    cursor.executemany(INSERT OR IGNORE INTO issue_types (name) VALUES (), issue_types)

    # Insert some default users (for testing)
    # Admin user
    admin_password_hash = generate_password_hash(adminpass, salt_length=16) # Stronger salt_length
    cursor.execute(
        INSERT OR IGNORE INTO users (username, password_hash, role, department, full_name) VALUES (, , , , ),
        (it.admin, admin_password_hash, admin, IT Department, IT Lead)
    )
    
    # Staff users
    staff_password_hash = generate_password_hash(staffpass, salt_length=16)
    cursor.execute(
        INSERT OR IGNORE INTO users (username, password_hash, role, department, full_name) VALUES (, , , , ),
        (dr.john, staff_password_hash, staff, Radiology, Dr. John Doe)
    )
    cursor.execute(
        INSERT OR IGNORE INTO users (username, password_hash, role, department, full_name) VALUES (, , , , ),
        (nurse.mary, staff_password_hash, staff, Inpatient Services, Nurse Mary)
    )

    conn.commit()
    conn.close()

if __name__ == '__main__'
    print(Initializing database...)
    init_db()
    print(Database initialized successfully with default data.)