# initialize_db.py

import os
from flask import Flask
import sqlite3 # Keep for local fallback
import psycopg2 # Keep for potential future PostgreSQL
from urllib.parse import urlparse # Keep for potential future PostgreSQL

# --- Replicate the database connection logic from app.py ---
DATABASE_URL = os.environ.get("DATABASE_URL")

if DATABASE_URL is None:
    # IMPORTANT: Adjust this path 'database.db' to your ACTUAL local SQLite DB path.
    # This MUST match the path you set in app.py for local development.
    LOCAL_DATABASE_PATH = 'database.db' # <--- **ADJUST THIS LINE IF YOUR LOCAL DB IS IN A SUBFOLDER**
    DB_CONNECTION_STRING = LOCAL_DATABASE_PATH
    IS_POSTGRES = False
else:
    DB_CONNECTION_STRING = DATABASE_URL
    IS_POSTGRES = True

# --- Create a minimal Flask app instance just for context ---
# We need a Flask app context to run init_db()
app = Flask(__name__)

# --- Replicate get_db() from app.py (or adapt if it's truly in database.py) ---
# This is a simplified get_db for initialization purposes
# It assumes g.db and g.pop are not strictly needed for init_db if it opens/closes its own connection
# However, if init_db relies on Flask's g object, we need to ensure it's available.

# For now, let's assume init_db directly calls sqlite3.connect or psycopg2.connect
# If init_db relies on app.app_context() and g, then we need to be careful.
# Let's try to make a direct connection for init_db, assuming it creates tables.

# If your database.py's init_db() directly uses sqlite3.connect(DATABASE)
# and DATABASE is a global variable in database.py, then we need to ensure that variable
# is set correctly for PythonAnywhere's MySQL.

# Let's assume init_db() is self-contained or uses a global DATABASE variable.
# If init_db() relies on the get_db() from app.py, then this script needs to replicate that.

# --- Let's make init_db() directly connect for this script ---
# This is a temporary solution for the initialization script.
# Your actual app.py's get_db() will still handle runtime connections.

def get_db_for_init():
    if IS_POSTGRES:
        result = urlparse(DB_CONNECTION_STRING)
        conn = psycopg2.connect(
            database=result.path[1:],
            user=result.username,
            password=result.password,
            host=result.hostname,
            port=result.port
        )
    else:
        # For PythonAnywhere, the DATABASE_URL will be for MySQL.
        # Your current init_db() in database.py likely uses sqlite3.connect().
        # This is the point of conflict.
        # PythonAnywhere's free tier provides MySQL.
        # We need to ensure init_db() knows how to connect to MySQL.

        # If your database.py init_db() uses sqlite3 directly:
        # We need to change database.py to use a MySQL connector if IS_POSTGRES is False
        # and DATABASE_URL is set (meaning we are on PythonAnywhere).

        # For now, let's assume init_db() is smart enough or we'll fix database.py next.
        # This line will only run if DATABASE_URL is None (local dev)
        conn = sqlite3.connect(DB_CONNECTION_STRING)
    return conn

# --- Import init_db from your database.py ---
from database import init_db

# --- Run init_db within the Flask app context ---
with app.app_context():
    # This will call the init_db function from your database.py
    # It needs to be able to connect to the database.
    init_db()
    print("Database initialization script finished.")