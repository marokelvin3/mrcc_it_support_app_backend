# init_script.py

import sys
import os

# Add the current directory to the Python path
# This ensures 'app' and 'database' modules can be found
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import app
import database

print("Attempting to initialize database...")
with app.app.app_context():
    database.init_db()
print("Database initialization process completed.")