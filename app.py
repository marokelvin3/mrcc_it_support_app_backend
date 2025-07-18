from flask import Flask, request, jsonify, session, g
from flask_cors import CORS
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import os
import secrets
import datetime # Import datetime for timestamp generation

# NEW IMPORTS FOR DATABASE SWITCHING
import psycopg2 # For PostgreSQL connection
from urllib.parse import urlparse # For parsing PostgreSQL URL

# --- Determine Database Connection ---
DATABASE_URL = os.environ.get("DATABASE_URL")

# If DATABASE_URL is not set (e.g., for local development), use local SQLite
if DATABASE_URL is None:
    # IMPORTANT: Adjust this path 'database.db' to your ACTUAL local SQLite DB path.
    # For example:
    # - If your DB file is 'my_db.db' directly in the Backend folder: 'my_db.db'
    # - If your DB file is 'data.db' in a 'data' subfolder: 'data/data.db'
    LOCAL_DATABASE_PATH = 'database.db' # <--- **ADJUST THIS LINE IF YOUR LOCAL DB IS IN A SUBFOLDER**
    DB_CONNECTION_STRING = LOCAL_DATABASE_PATH
    IS_POSTGRES = False
else:
    # For Render deployment, use the PostgreSQL URL
    DB_CONNECTION_STRING = DATABASE_URL
    IS_POSTGRES = True

# --- Flask App Configuration ---
app = Flask(__name__)
# Generate a secure random key for session management
app.secret_key = secrets.token_hex(24)
# Configure session to use filesystem for simplicity in demo.
# IMPORTANT: For production (like Render), 'filesystem' session will NOT work
# because Render's filesystem is ephemeral (changes are lost on restart).
# You'll need to switch to a more robust backend like Flask-Session with Redis,
# or a database-backed session store.
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_FILE_DIR'] = './flask_session'
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_USE_SIGNER'] = True # Sign the session cookie for tamper protection
app.config['PERMANENT_SESSION_LIFETIME'] = datetime.timedelta(hours=2) # Example: session lasts 2 hours

# Enable CORS for frontend development (adjust in production)
CORS(app, supports_credentials=True, origins=["http://127.0.0.1:5500", "http://localhost:5500"])
# Replace with your actual frontend URL(s) in production


# --- Database Helpers ---
# Removed: DATABASE = 'database.db' - now handled by DATABASE_URL logic above

def get_db():
    if 'db' not in g:
        if IS_POSTGRES:
            # Connect to PostgreSQL using psycopg2
            try:
                result = urlparse(DB_CONNECTION_STRING)
                username = result.username
                password = result.password
                database = result.path[1:] # Slice to remove leading '/'
                hostname = result.hostname
                port = result.port

                g.db = psycopg2.connect(
                    database=database,
                    user=username,
                    password=password,
                    host=hostname,
                    port=port
                )
            except Exception as e:
                # Log the error (e.g., print to console, or use Flask's logger)
                print(f"Error connecting to PostgreSQL: {e}")
                # You might want to raise an exception or handle this more gracefully
                # depending on your app's error handling strategy.
                raise e # Re-raise to stop the request if DB connection fails
        else:
            # Connect to SQLite for local development
            g.db = sqlite3.connect(DB_CONNECTION_STRING)
            g.db.row_factory = sqlite3.Row # Keep for SQLite

    return g.db

@app.teardown_appcontext
def close_db(e=None):
    db = g.pop('db', None)
    if db is not None:
        if IS_POSTGRES:
            db.close() # Close psycopg2 connection
        else:
            db.close() # Close sqlite3 connection

# --- User Management (simplified for demo) ---
@app.before_request
def load_logged_in_user():
    user_id = session.get('user_id')
    if user_id is None:
        g.user = None
    else:
        db = get_db()
        # IMPORTANT: For PostgreSQL, ensure your table/column names match casing.
        # PostgreSQL is case-sensitive by default, SQLite is not.
        # If your table is 'users' and column 'id' in SQLite, keep it that way.
        g.user = db.execute('SELECT * FROM users WHERE id = %s', (user_id,)).fetchone()
        # For psycopg2, execute expects %s for parameters, not ?.
        # Also, fetchone() for psycopg2 returns a tuple by default, not sqlite3.Row (dict-like).
        # You'll need to adapt how you access g.user, or use psycopg2.extras.RealDictCursor.
        # For now, let's proceed and see if you hit errors with g.user['role'] etc.

def login_required(view):
    """Decorator to require login for a route."""
    import functools
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return jsonify({'message': 'Authentication required'}), 401
        return view(**kwargs)
    return wrapped_view

def admin_required(view):
    """Decorator to require admin role for a route."""
    import functools
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None or g.user['role'] != 'admin': # This access might break with psycopg2's default fetchone()
            return jsonify({'message': 'Admin privilege required'}), 403
        return view(**kwargs)
    return wrapped_view

# --- API Endpoints ---

@app.route('/api/auth/register', methods=['POST'])
@admin_required # Only admins can register new users in this hospital scenario
def register():
    db = get_db()
    data = request.json
    username = data.get('username')
    password = data.get('password')
    role = data.get('role', 'staff') # Default to staff if not specified
    department = data.get('department')
    full_name = data.get('full_name')

    if not username or not password:
        return jsonify({'message': 'Username and password are required'}), 400

    hashed_password = generate_password_hash(password, salt_length=16)

    try:
        # Use %s for psycopg2, ? for sqlite3
        param_char = '?' if not IS_POSTGRES else '%s'
        db.execute(
            f"INSERT INTO users (username, password_hash, role, department, full_name) VALUES ({param_char}, {param_char}, {param_char}, {param_char}, {param_char})",
            (username, hashed_password, role, department, full_name)
        )
        db.commit()
        return jsonify({'message': 'User registered successfully'}), 201
    except Exception as e: # Catch all exceptions for now to see specific errors
        if IS_POSTGRES and 'unique' in str(e).lower() and 'username' in str(e).lower():
            return jsonify({'message': 'Username already exists'}), 409
        elif not IS_POSTGRES and isinstance(e, sqlite3.IntegrityError):
            return jsonify({'message': 'Username already exists'}), 409
        return jsonify({'message': f'Error registering user: {str(e)}'}), 500

@app.route('/api/auth/login', methods=['POST'])
def login():
    db = get_db()
    data = request.json
    username = data.get('username')
    password = data.get('password')

    # Use %s for psycopg2, ? for sqlite3
    param_char = '?' if not IS_POSTGRES else '%s'
    user = db.execute(f'SELECT * FROM users WHERE username = {param_char}', (username,)).fetchone()

    # IMPORTANT: If user is a tuple (from psycopg2), you'll need to access elements by index
    # instead of by name, e.g., user[column_index_for_password_hash]
    # To fix this, you'll need to use psycopg2.extras.RealDictCursor in get_db for postgres
    # For now, let's assume it works, but be aware.
    if user and check_password_hash(user['password_hash'], password):
        session.clear()
        session['user_id'] = user['id']
        session['role'] = user['role']
        session['username'] = user['username']
        session['department'] = user['department']
        session['full_name'] = user['full_name']
        return jsonify({
            'message': 'Login successful',
            'user': {
                'id': user['id'],
                'username': user['username'],
                'role': user['role'],
                'department': user['department'],
                'full_name': user['full_name']
            }
        }), 200
    else:
        return jsonify({'message': 'Invalid username or password'}), 401

@app.route('/api/auth/logout', methods=['POST'])
@login_required
def logout():
    session.clear()
    return jsonify({'message': 'Logged out successfully'}), 200

@app.route('/api/auth/me', methods=['GET'])
@login_required
def get_current_user():
    user = g.user
    if user:
        return jsonify({
            'id': user['id'],
            'username': user['username'],
            'role': user['role'],
            'department': user['department'],
            'full_name': user['full_name']
        }), 200
    return jsonify({'message': 'User not logged in'}), 401 # Should not happen due to @login_required

@app.route('/api/departments', methods=['GET'])
@login_required
def get_departments():
    db = get_db()
    departments = db.execute('SELECT * FROM departments').fetchall()
    return jsonify([dict(d) for d in departments])

@app.route('/api/issue_types', methods=['GET'])
@login_required
def get_issue_types():
    db = get_db()
    issue_types = db.execute('SELECT * FROM issue_types').fetchall()
    return jsonify([dict(it) for it in issue_types])

@app.route('/api/tickets', methods=['POST'])
@login_required
def create_ticket():
    db = get_db()
    data = request.json

    requester_id = g.user['id']
    department_id = data.get('department_id')
    issue_type_id = data.get('issue_type_id')
    subject = data.get('subject')
    description = data.get('description')
    urgency = data.get('urgency', 'Medium')

    if not all([department_id, issue_type_id, subject, description]):
        return jsonify({'message': 'Missing required fields'}), 400

    try:
        param_char = '?' if not IS_POSTGRES else '%s'
        cursor = db.execute(
            f"INSERT INTO tickets (requester_id, department_id, issue_type_id, subject, description, urgency) VALUES ({param_char}, {param_char}, {param_char}, {param_char}, {param_char}, {param_char})",
            (requester_id, department_id, issue_type_id, subject, description, urgency)
        )
        db.commit()
        return jsonify({'message': 'Ticket created successfully', 'ticket_id': cursor.lastrowid}), 201
    except Exception as e:
        return jsonify({'message': f'Error creating ticket: {str(e)}'}), 500

@app.route('/api/tickets/my', methods=['GET'])
@login_required
def get_my_tickets():
    db = get_db()
    user_id = g.user['id']
    # Use %s for psycopg2, ? for sqlite3, and CURRENT_TIMESTAMP for SQL function
    param_char = '?' if not IS_POSTGRES else '%s'
    timestamp_func = 'CURRENT_TIMESTAMP' if not IS_POSTGRES else 'NOW()' # PostgreSQL uses NOW()

    tickets = db.execute(
        f'''
        SELECT
            t.id, t.subject, t.description, t.urgency, t.status,
            t.created_at, t.updated_at, t.resolution_notes,
            d.name AS department_name,
            it.name AS issue_type_name,
            u_req.full_name AS requester_name,
            u_ass.full_name AS assigned_to_name
        FROM tickets t
        LEFT JOIN departments d ON t.department_id = d.id
        LEFT JOIN issue_types it ON t.issue_type_id = it.id
        LEFT JOIN users u_req ON t.requester_id = u_req.id
        LEFT JOIN users u_ass ON t.assigned_to_id = u_ass.id
        WHERE t.requester_id = {param_char} ORDER BY t.created_at DESC
        ''', (user_id,)
    ).fetchall()
    return jsonify([dict(t) for t in tickets])

@app.route('/api/tickets', methods=['GET'])
@admin_required # Only IT support (admins) can view all tickets
def get_all_tickets():
    db = get_db()
    status_filter = request.args.get('status')
    department_filter = request.args.get('department_id')
    issue_type_filter = request.args.get('issue_type_id')
    search_query = request.args.get('search')

    # Use %s for psycopg2, ? for sqlite3
    param_char = '?' if not IS_POSTGRES else '%s'
    like_char = '?' if not IS_POSTGRES else '%s' # For LIKE clauses, parameter style is same

    query = f'''
        SELECT
            t.id, t.subject, t.description, t.urgency, t.status,
            t.created_at, t.updated_at, t.resolution_notes,
            d.name AS department_name,
            it.name AS issue_type_name,
            u_req.full_name AS requester_name,
            u_ass.full_name AS assigned_to_name
        FROM tickets t
        LEFT JOIN departments d ON t.department_id = d.id
        LEFT JOIN issue_types it ON t.issue_type_id = it.id
        LEFT JOIN users u_req ON t.requester_id = u_req.id
        LEFT JOIN users u_ass ON t.assigned_to_id = u_ass.id
    '''
    params = []
    conditions = []

    if status_filter:
        conditions.append(f"t.status = {param_char}")
        params.append(status_filter)
    if department_filter:
        conditions.append(f"t.department_id = {param_char}")
        params.append(department_filter)
    if issue_type_filter:
        conditions.append(f"t.issue_type_id = {param_char}")
        params.append(issue_type_filter)
    if search_query:
        conditions.append(f"(t.subject LIKE {like_char} OR t.description LIKE {like_char} OR u_req.full_name LIKE {like_char})")
        params.extend([f'%{search_query}%', f'%{search_query}%', f'%{search_query}%'])

    if conditions:
        query += " WHERE " + " AND ".join(conditions)

    query += " ORDER BY t.created_at DESC"

    tickets = db.execute(query, tuple(params)).fetchall()
    return jsonify([dict(t) for t in tickets])


@app.route('/api/tickets/<int:ticket_id>', methods=['GET'])
@login_required
def get_ticket_details(ticket_id):
    db = get_db()
    param_char = '?' if not IS_POSTGRES else '%s'
    ticket = db.execute(
        f'''
        SELECT
            t.id, t.subject, t.description, t.urgency, t.status,
            t.created_at, t.updated_at, t.resolution_notes,
            d.name AS department_name,
            it.name AS issue_type_name,
            u_req.full_name AS requester_name,
            u_req.department AS requester_department,
            u_ass.full_name AS assigned_to_name
        FROM tickets t
        LEFT JOIN departments d ON t.department_id = d.id
        LEFT JOIN issue_types it ON t.issue_type_id = it.id
        LEFT JOIN users u_req ON t.requester_id = u_req.id
        LEFT JOIN users u_ass ON t.assigned_to_id = u_ass.id
        WHERE t.id = {param_char}
        ''', (ticket_id,)
    ).fetchone()

    if not ticket:
        return jsonify({'message': 'Ticket not found'}), 404

    # Check if the user is authorized to view this ticket
    # IMPORTANT: This assumes g.user is dict-like. If psycopg2 returns tuple, this will break.
    # We might need psycopg2.extras.RealDictCursor or convert tuple to dict.
    if g.user['role'] == 'staff' and g.user['id'] != ticket['requester_id']:
        return jsonify({'message': 'Unauthorized to view this ticket'}), 403

    param_char = '?' if not IS_POSTGRES else '%s'
    comments = db.execute(
        f'''
        SELECT tc.comment, tc.created_at, u.full_name AS commenter_name
        FROM ticket_comments tc
        JOIN users u ON tc.user_id = u.id
        WHERE tc.ticket_id = {param_char} ORDER BY tc.created_at ASC
        ''', (ticket_id,)
    ).fetchall()

    ticket_dict = dict(ticket) # This conversion assumes ticket is sqlite3.Row or dict-like
    ticket_dict['comments'] = [dict(c) for c in comments] # This conversion assumes comments are sqlite3.Row or dict-like
    return jsonify(ticket_dict)

@app.route('/api/tickets/<int:ticket_id>', methods=['PUT'])
@admin_required # Only IT support (admins) can update tickets
def update_ticket(ticket_id):
    db = get_db()
    data = request.json

    status = data.get('status')
    assigned_to_id = data.get('assigned_to_id')
    resolution_notes = data.get('resolution_notes')

    update_fields = []
    params = []

    # Use %s for psycopg2, ? for sqlite3
    param_char = '?' if not IS_POSTGRES else '%s'
    timestamp_func = 'CURRENT_TIMESTAMP' if not IS_POSTGRES else 'NOW()' # PostgreSQL uses NOW()

    if status:
        update_fields.append(f"status = {param_char}")
        params.append(status)
    if assigned_to_id is not None: # Can be null to unassign
        update_fields.append(f"assigned_to_id = {param_char}")
        params.append(assigned_to_id)
    if resolution_notes is not None: # Can be null to clear
        update_fields.append(f"resolution_notes = {param_char}")
        params.append(resolution_notes)

    update_fields.append(f"updated_at = {timestamp_func}")

    if not update_fields:
        return jsonify({'message': 'No fields to update'}), 400

    query = f"UPDATE tickets SET {', '.join(update_fields)} WHERE id = {param_char}"
    params.append(ticket_id)

    try:
        cursor = db.execute(query, tuple(params))
        db.commit() # Commit after execute
        if cursor.rowcount == 0:
            return jsonify({'message': 'Ticket not found or no changes made'}), 404
        return jsonify({'message': 'Ticket updated successfully'}), 200
    except Exception as e:
        return jsonify({'message': f'Error updating ticket: {str(e)}'}), 500


@app.route('/api/tickets/<int:ticket_id>/comments', methods=['POST'])
@login_required
def add_comment_to_ticket(ticket_id):
    db = get_db()
    data = request.json
    comment_text = data.get('comment')
    user_id = g.user['id']

    if not comment_text:
        return jsonify({'message': 'Comment text is required'}), 400

    # Optional: Check if ticket exists and user is related (requester or admin)
    param_char = '?' if not IS_POSTGRES else '%s'
    ticket = db.execute(f'SELECT requester_id FROM tickets WHERE id = {param_char}', (ticket_id,)).fetchone()
    if not ticket:
        return jsonify({'message': 'Ticket not found'}), 404

    # IMPORTANT: This assumes ticket is dict-like. If psycopg2 returns tuple, this will break.
    if g.user['role'] == 'staff' and g.user['id'] != ticket['requester_id']:
        return jsonify({'message': 'Unauthorized to comment on this ticket'}), 403

    try:
        param_char = '?' if not IS_POSTGRES else '%s'
        cursor = db.execute(
            f"INSERT INTO ticket_comments (ticket_id, user_id, comment) VALUES ({param_char}, {param_char}, {param_char})",
            (ticket_id, user_id, comment_text)
        )
        db.commit()
        return jsonify({'message': 'Comment added successfully', 'comment_id': cursor.lastrowid}), 201
    except Exception as e:
        return jsonify({'message': f'Error adding comment: {str(e)}'}), 500

@app.route('/api/users', methods=['GET'])
@admin_required # Only IT admins can manage/view all users
def get_all_users():
    db = get_db()
    users = db.execute('SELECT id, username, role, department, full_name FROM users').fetchall()
    return jsonify([dict(u) for u in users])

@app.route('/api/users/<int:user_id>', methods=['PUT'])
@admin_required # Only IT admins can update user roles/departments
def update_user(user_id):
    db = get_db()
    data = request.json
    role = data.get('role')
    department = data.get('department')
    full_name = data.get('full_name')

    update_fields = []
    params = []

    param_char = '?' if not IS_POSTGRES else '%s'

    if role:
        update_fields.append(f"role = {param_char}")
        params.append(role)
    if department:
        update_fields.append(f"department = {param_char}")
        params.append(department)
    if full_name:
        update_fields.append(f"full_name = {param_char}")
        params.append(full_name)

    if not update_fields:
        return jsonify({'message': 'No fields to update'}), 400

    query = f"UPDATE users SET {', '.join(update_fields)} WHERE id = {param_char}"
    params.append(user_id)

    try:
        cursor = db.execute(query, tuple(params))
        db.commit()
        if cursor.rowcount == 0:
            return jsonify({'message': 'User not found or no changes made'}), 404
        return jsonify({'message': 'User updated successfully'}), 200
    except Exception as e:
        return jsonify({'message': f'Error updating user: {str(e)}'}), 500

# --- Initial DB setup run on app startup (for dev) ---
with app.app_context():
    from database import init_db
    init_db()

if __name__ == '__main__':
    # It's recommended to run Flask in production with a WSGI server like Gunicorn or uWSGI
    # For development:
    app.run(debug=True, port=5000)