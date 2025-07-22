# database.py

import os
import pymysql # NEW: Import PyMySQL for MySQL connection
import sqlite3 # Keep for local development fallback (if needed)
from werkzeug.security import generate_password_hash # Already present
from urllib.parse import urlparse # To parse DATABASE_URL if it's a full URL

# --- Database Connection Logic ---
# PythonAnywhere provides DATABASE_URL for MySQL.
# For local development, we'll use SQLite.

# Get database URL from environment variable (for PythonAnywhere MySQL)
# If not set, fallback to local SQLite.
DATABASE_URL = os.environ.get("DATABASE_URL")

# Determine if we are connecting to MySQL or SQLite
IS_MYSQL = False
LOCAL_SQLITE_DB_PATH = 'database.db' # <--- IMPORTANT: Adjust this if your local SQLite is in a subfolder

if DATABASE_URL:
    # If DATABASE_URL is set, assume it's for MySQL (from PythonAnywhere)
    IS_MYSQL = True
    # Parse the URL to get individual connection components for PyMySQL
    result = urlparse(DATABASE_URL)
    DB_HOST = result.hostname
    DB_PORT = result.port or 3306 # Default MySQL port
    DB_USER = result.username
    DB_PASSWORD = result.password
    DB_NAME = result.path[1:] # Remove leading '/'
else:
    # If DATABASE_URL is not set, use local SQLite for development
    pass # Variables for MySQL are not needed here, SQLite uses LOCAL_SQLITE_DB_PATH

def get_db():
    # This get_db is for direct use by init_db, not Flask's g object
    if IS_MYSQL:
        # Connect to MySQL using PyMySQL
        try:
            conn = pymysql.connect(
                host=DB_HOST,
                port=DB_PORT,
                user=DB_USER,
                password=DB_PASSWORD,
                database=DB_NAME,
                cursorclass=pymysql.cursors.DictCursor # To get dict-like rows
            )
            return conn
        except Exception as e:
            print(f"Error connecting to MySQL: {e}")
            raise e
    else:
        # Connect to SQLite for local development
        conn = sqlite3.connect(LOCAL_SQLITE_DB_PATH)
        conn.row_factory = sqlite3.Row # To get dict-like rows for SQLite
        return conn

def init_db():
    # Only remove the database file if it's SQLite (local development)
    if not IS_MYSQL and os.path.exists(LOCAL_SQLITE_DB_PATH):
        os.remove(LOCAL_SQLITE_DB_PATH)
        print(f"Removed existing SQLite database: {LOCAL_SQLITE_DB_PATH}")

    conn = get_db() # Get the correct connection (MySQL or SQLite)
    cursor = conn.cursor()

    # Define SQL statements based on database type
    if IS_MYSQL:
        # MySQL-specific SQL
        users_table_sql = '''
            CREATE TABLE IF NOT EXISTS users (
                id INT PRIMARY KEY AUTO_INCREMENT,
                username VARCHAR(255) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                role VARCHAR(50) NOT NULL DEFAULT 'staff', -- 'staff' or 'admin'
                department VARCHAR(255),
                full_name VARCHAR(255)
            );
        '''
        departments_table_sql = '''
            CREATE TABLE IF NOT EXISTS departments (
                id INT PRIMARY KEY AUTO_INCREMENT,
                name VARCHAR(255) UNIQUE NOT NULL
            );
        '''
        issue_types_table_sql = '''
            CREATE TABLE IF NOT EXISTS issue_types (
                id INT PRIMARY KEY AUTO_INCREMENT,
                name VARCHAR(255) UNIQUE NOT NULL
            );
        '''
        tickets_table_sql = '''
            CREATE TABLE IF NOT EXISTS tickets (
                id INT PRIMARY KEY AUTO_INCREMENT,
                requester_id INT NOT NULL,
                department_id INT,
                issue_type_id INT,
                subject VARCHAR(255) NOT NULL,
                description TEXT,
                urgency VARCHAR(50) NOT NULL DEFAULT 'Medium',
                status VARCHAR(50) NOT NULL DEFAULT 'Open',
                assigned_to_id INT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                resolution_notes TEXT,
                FOREIGN KEY (requester_id) REFERENCES users(id),
                FOREIGN KEY (department_id) REFERENCES departments(id),
                FOREIGN KEY (issue_type_id) REFERENCES issue_types(id),
                FOREIGN KEY (assigned_to_id) REFERENCES users(id)
            );
        '''
        ticket_comments_table_sql = '''
            CREATE TABLE IF NOT EXISTS ticket_comments (
                id INT PRIMARY KEY AUTO_INCREMENT,
                ticket_id INT NOT NULL,
                user_id INT NOT NULL,
                comment TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (ticket_id) REFERENCES tickets(id),
                FOREIGN KEY (user_id) REFERENCES users(id)
            );
        '''
        insert_ignore_syntax = 'INSERT IGNORE INTO'
        param_placeholder = '%s'
    else:
        # SQLite-specific SQL
        users_table_sql = '''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'staff', -- 'staff' or 'admin'
                department TEXT,
                full_name TEXT
            );
        '''
        departments_table_sql = '''
            CREATE TABLE IF NOT EXISTS departments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL
            );
        '''
        issue_types_table_sql = '''
            CREATE TABLE IF NOT EXISTS issue_types (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL
            );
        '''
        tickets_table_sql = '''
            CREATE TABLE IF NOT EXISTS tickets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                requester_id INTEGER NOT NULL,
                department_id INTEGER,
                issue_type_id INTEGER,
                subject TEXT NOT NULL,
                description TEXT,
                urgency TEXT NOT NULL DEFAULT 'Medium',
                status TEXT NOT NULL DEFAULT 'Open',
                assigned_to_id INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                resolution_notes TEXT,
                FOREIGN KEY (requester_id) REFERENCES users(id),
                FOREIGN KEY (department_id) REFERENCES departments(id),
                FOREIGN KEY (issue_type_id) REFERENCES issue_types(id),
                FOREIGN KEY (assigned_to_id) REFERENCES users(id)
            );
        '''
        ticket_comments_table_sql = '''
            CREATE TABLE IF NOT EXISTS ticket_comments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ticket_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                comment TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (ticket_id) REFERENCES tickets(id),
                FOREIGN KEY (user_id) REFERENCES users(id)
            );
        '''
        insert_ignore_syntax = 'INSERT OR IGNORE INTO'
        param_placeholder = '?'

    # Execute table creation
    cursor.execute(users_table_sql)
    cursor.execute(departments_table_sql)
    cursor.execute(issue_types_table_sql)
    cursor.execute(tickets_table_sql)
    cursor.execute(ticket_comments_table_sql)

    # Insert initial data
    departments_data = [
        ('Radiology',), ('Radiotherapy',), ('Outpatient Services',),
        ('Inpatient Services',), ('IT Department',), ('Administration',)
    ]
    cursor.executemany(f'{insert_ignore_syntax} departments (name) VALUES ({param_placeholder})', departments_data)

    issue_types_data = [
        ('Network Issue',), ('Printer Issue',), ('EMR Issue',),
        ('EMR Service UploadUpdate',), ('EMR New User Creation',),
        ('New Email in AD Creation',), ('Hardware Issue',), ('Software Issue',)
    ]
    cursor.executemany(f'{insert_ignore_syntax} issue_types (name) VALUES ({param_placeholder})', issue_types_data)

    admin_password_hash = generate_password_hash('adminpass', salt_length=16)
    cursor.execute(
        f'{insert_ignore_syntax} users (username, password_hash, role, department, full_name) VALUES ({param_placeholder}, {param_placeholder}, {param_placeholder}, {param_placeholder}, {param_placeholder})',
        ('it.admin', admin_password_hash, 'admin', 'IT Department', 'IT Lead')
    )
    staff_password_hash = generate_password_hash('staffpass', salt_length=16)
    cursor.execute(
        f'{insert_ignore_syntax} users (username, password_hash, role, department, full_name) VALUES ({param_placeholder}, {param_placeholder}, {param_placeholder}, {param_placeholder}, {param_placeholder})',
        ('dr.john', staff_password_hash, 'staff', 'Radiology', 'Dr. John Doe')
    )
    cursor.execute(
        f'{insert_ignore_syntax} users (username, password_hash, role, department, full_name) VALUES ({param_placeholder}, {param_placeholder}, {param_placeholder}, {param_placeholder}, {param_placeholder})',
        ('nurse.mary', staff_password_hash, 'staff', 'Inpatient Services', 'Nurse Mary')
    )
    conn.commit()
    conn.close()
    print("Database initialized successfully with default data.")

if __name__ == '__main__':
    print("Initializing database from direct script run...")
    init_db()
    print("Database initialization script finished.")