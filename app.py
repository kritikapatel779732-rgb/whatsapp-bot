from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import threading
import time
import os
import json
import random
import secrets
import hashlib
import gspread
from google.oauth2 import service_account
from datetime import datetime
from functools import wraps
from config import Config

app = Flask(__name__, static_folder='.', static_url_path='')
app.config.from_object(Config)

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

CORS(app)

# Google Sheets Manager
class GoogleSheetsManager:
    def __init__(self):
        self.client = self.get_google_sheets_client()
        # Wait a bit for the sheet to be accessible
        time.sleep(2)
        try:
            self.master_sheet = self.client.open_by_url(Config.MASTER_SHEET_URL)
            print("✅ Connected to existing master sheet")
        except Exception as e:
            print(f"❌ Error opening sheet: {e}")
            # Try to create the sheet if it doesn't exist
            self.setup_master_sheet()
        
    def get_google_sheets_client(self):
        # Use environment variables instead of credentials file
        creds_dict = Config.GOOGLE_SHEETS_CREDENTIALS
        creds = service_account.Credentials.from_service_account_info(
            creds_dict,
            scopes=['https://www.googleapis.com/auth/spreadsheets']
        )
        return gspread.authorize(creds)
    
    def setup_master_sheet(self):
        """Create the master sheet if it doesn't exist"""
        try:
            # Create new spreadsheet
            new_sheet = self.client.create('WhatsApp Bot Master Database')
            
            # Create worksheets
            users_sheet = new_sheet.add_worksheet(title="users", rows="1000", cols="10")
            user_data_sheet = new_sheet.add_worksheet(title="user_data", rows="1000", cols="10")
            
            # Setup headers
            users_sheet.update('A1:F1', [['Email', 'Password Hash', 'Secret Key', 'Credits', 'Status', 'Created At']])
            user_data_sheet.update('A1:F1', [['Email', 'Session ID', 'Phone Numbers', 'Messages', 'Status', 'Last Updated']])
            
            # Format headers
            users_sheet.format('A1:F1', {'textFormat': {'bold': True}})
            user_data_sheet.format('A1:F1', {'textFormat': {'bold': True}})
            
            # Delete default first sheet
            default_sheet = new_sheet.sheet1
            new_sheet.del_worksheet(default_sheet)
            
            # Share publicly (view only) - or keep private
            new_sheet.share(None, perm_type='anyone', role='writer')
            
            print(f"✅ Created new master sheet: {new_sheet.url}")
            self.master_sheet = new_sheet
            
            # Update the config with new sheet URL
            global Config
            Config.MASTER_SHEET_URL = new_sheet.url
            
        except Exception as e:
            print(f"❌ Error creating master sheet: {e}")
    
    def get_users_sheet(self):
        return self.master_sheet.worksheet("users")
    
    def get_user_data_sheet(self):
        return self.master_sheet.worksheet("user_data")
    
    def user_exists(self, email):
        try:
            users_sheet = self.get_users_sheet()
            users = users_sheet.get_all_records()
            for user in users:
                if user.get('email', '').lower() == email.lower():
                    return True
            return False
        except Exception as e:
            print(f"Error checking user: {e}")
            return False
    
    def create_user(self, email, password):
        try:
            users_sheet = self.get_users_sheet()
            
            # Generate unique secret key
            secret_key = f"sk_{secrets.token_hex(16)}"
            
            # Add user to master sheet
            users_sheet.append_row([
                email.lower(),
                hashlib.sha256(password.encode()).hexdigest(),
                secret_key,
                100,  # initial credits
                "active",
                datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            ])
            
            return secret_key
        except Exception as e:
            print(f"Error creating user: {e}")
            return None
    
    def authenticate_user(self, email, password):
        try:
            users_sheet = self.get_users_sheet()
            users = users_sheet.get_all_records()
            
            password_hash = hashlib.sha256(password.encode()).hexdigest()
            
            for user in users:
                if (user.get('email', '').lower() == email.lower() and 
                    user.get('password_hash') == password_hash):
                    return {
                        'email': user.get('email'),
                        'secret_key': user.get('secret_key'),
                        'credits': user.get('credits', 100),
                        'status': user.get('status', 'active')
                    }
            return None
        except Exception as e:
            print(f"Auth error: {e}")
            return None
    
    def get_user_by_secret(self, secret_key):
        try:
            users_sheet = self.get_users_sheet()
            users = users_sheet.get_all_records()
            
            for user in users:
                if user.get('secret_key') == secret_key:
                    return {
                        'email': user.get('email'),
                        'secret_key': user.get('secret_key'),
                        'credits': user.get('credits', 100),
                        'status': user.get('status', 'active')
                    }
            return None
        except Exception as e:
            print(f"Error getting user: {e}")
            return None
    
    def save_user_data(self, email, phone_numbers, messages, statuses):
        try:
            user_data_sheet = self.get_user_data_sheet()
            
            # Convert lists to JSON strings for storage
            phones_json = json.dumps(phone_numbers)
            messages_json = json.dumps(messages)
            statuses_json = json.dumps(statuses)
            
            # Find if user already has data
            all_data = user_data_sheet.get_all_records()
            for i, data in enumerate(all_data, start=2):
                if data.get('email', '').lower() == email.lower():
                    # Update existing data
                    user_data_sheet.update(f'C{i}:F{i}', [[phones_json, messages_json, statuses_json, datetime.now().strftime("%Y-%m-%d %H:%M:%S")]])
                    return True
            
            # Add new data
            user_data_sheet.append_row([
                email.lower(),
                f"session_{int(time.time())}",
                phones_json,
                messages_json,
                statuses_json,
                datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            ])
            return True
            
        except Exception as e:
            print(f"Error saving user data: {e}")
            return False
    
    def get_user_data(self, email):
        try:
            user_data_sheet = self.get_user_data_sheet()
            all_data = user_data_sheet.get_all_records()
            
            for data in all_data:
                if data.get('email', '').lower() == email.lower():
                    # Parse JSON strings back to lists
                    phones = json.loads(data.get('phone_numbers', '[]'))
                    messages = json.loads(data.get('messages', '[]'))
                    statuses = json.loads(data.get('status', '[]'))
                    
                    return {
                        'phone_numbers': phones,
                        'messages': messages,
                        'statuses': statuses,
                        'last_updated': data.get('last_updated')
                    }
            return None
        except Exception as e:
            print(f"Error getting user data: {e}")
            return None
    
    def update_user_credits(self, email, new_credits):
        try:
            users_sheet = self.get_users_sheet()
            users = users_sheet.get_all_records()
            
            for i, user in enumerate(users, start=2):
                if user.get('email', '').lower() == email.lower():
                    users_sheet.update_cell(i, 4, new_credits)  # Column D is credits
                    return True
            return False
        except Exception as e:
            print(f"Error updating credits: {e}")
            return False

# Initialize sheets manager
try:
    sheets_manager = GoogleSheetsManager()
    print("✅ Google Sheets Manager initialized successfully")
except Exception as e:
    print(f"❌ Failed to initialize Google Sheets Manager: {e}")
    sheets_manager = None

# Session Management
class SessionManager:
    def __init__(self):
        self.sessions = {}
    
    def add_session(self, session_id, session_data):
        self.sessions[session_id] = session_data
    
    def get_user_session(self, email):
        for session_id, session in self.sessions.items():
            if session.get('user_email') == email:
                return session
        return None
    
    def remove_session(self, session_id):
        if session_id in self.sessions:
            del self.sessions[session_id]

session_manager = SessionManager()

# Auth decorator
def auth_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            data = request.get_json() or {}
            secret_key = data.get('secret_key')
            
            if not secret_key:
                return jsonify({"error": "Secret key is required"}), 401
            
            user = sheets_manager.get_user_by_secret(secret_key)
            if not user:
                return jsonify({"error": "Invalid secret key"}), 401
            
            request.user = user
            return f(*args, **kwargs)
        except Exception as e:
            return jsonify({"error": "Authentication failed"}), 401
    return decorated_function

# Routes
@app.route('/')
def serve_frontend():
    return send_from_directory('.', 'index.html')

@app.route('/<path:path>')
def serve_static(path):
    return send_from_directory('.', path)

@app.route('/health')
def health():
    return jsonify({
        "status": "healthy", 
        "timestamp": datetime.now().isoformat(),
        "sheets_connected": sheets_manager is not None
    })

@app.route('/register', methods=['POST'])
@limiter.limit("5 per minute")
def register():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No data provided"}), 400
            
        email = data.get('email', '').strip().lower()
        password = data.get('password')
        
        if not email or not password:
            return jsonify({"error": "Email and password are required"}), 400
        
        if len(password) < 6:
            return jsonify({"error": "Password must be at least 6 characters"}), 400
        
        if sheets_manager.user_exists(email):
            return jsonify({"error": "Email already registered"}), 400
        
        secret_key = sheets_manager.create_user(email, password)
        
        if not secret_key:
            return jsonify({"error": "Registration failed. Please try again."}), 500
        
        return jsonify({
            "status": "success",
            "message": "Registration successful!",
            "secret_key": secret_key,
            "instructions": "Copy and save your secret key securely. You'll need it to login."
        })
        
    except Exception as e:
        print(f"Registration error: {e}")
        return jsonify({"error": "Registration failed"}), 500

@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No data provided"}), 400
            
        email = data.get('email', '').strip().lower()
        password = data.get('password')
        
        if not email or not password:
            return jsonify({"error": "Email and password are required"}), 400
        
        user = sheets_manager.authenticate_user(email, password)
        
        if not user:
            return jsonify({"error": "Invalid email or password"}), 401
        
        # Get user's previous data
        user_data = sheets_manager.get_user_data(email)
        
        return jsonify({
            "status": "success",
            "message": "Login successful",
            "secret_key": user['secret_key'],
            "credits": user.get('credits', 100),
            "user_data": user_data  # Send previous session data
        })
            
    except Exception as e:
        print(f"Login error: {e}")
        return jsonify({"error": "Login failed"}), 500

@app.route('/save_data', methods=['POST'])
@auth_required
def save_data():
    try:
        user = request.user
        data = request.get_json()
        
        phone_numbers = data.get('phone_numbers', [])
        messages = data.get('messages', [])
        statuses = data.get('statuses', ['Pending'] * len(phone_numbers))
        
        success = sheets_manager.save_user_data(
            user['email'], 
            phone_numbers, 
            messages, 
            statuses
        )
        
        if success:
            return jsonify({
                "status": "success", 
                "message": "Data saved successfully"
            })
        else:
            return jsonify({"error": "Failed to save data"}), 500
            
    except Exception as e:
        print(f"Save data error: {e}")
        return jsonify({"error": "Save failed"}), 500

@app.route('/get_data', methods=['POST'])
@auth_required
def get_data():
    try:
        user = request.user
        user_data = sheets_manager.get_user_data(user['email'])
        
        return jsonify({
            "status": "success",
            "user_data": user_data or {}
        })
        
    except Exception as e:
        print(f"Get data error: {e}")
        return jsonify({"error": "Failed to get data"}), 500

@app.route('/start_bot', methods=['POST'])
@auth_required
def start_bot():
    try:
        user = request.user
        
        if user.get('credits', 0) <= 0:
            return jsonify({"error": "Insufficient credits"}), 402
        
        # Deduct one credit
        new_credits = user.get('credits', 100) - 1
        sheets_manager.update_user_credits(user['email'], new_credits)
        
        # Get user's data
        user_data = sheets_manager.get_user_data(user['email'])
        
        session_id = f"session_{user['email']}_{int(time.time())}"
        
        # Start bot with user's data
        thread = threading.Thread(
            target=run_bot_for_user,
            args=(user['email'], user_data, session_id),
            daemon=True
        )
        thread.start()
        
        session_manager.add_session(session_id, {
            'user_email': user['email'],
            'status': 'running',
            'started_at': datetime.now().isoformat(),
            'thread': thread
        })
        
        return jsonify({
            "status": "success",
            "message": "Bot started successfully",
            "session_id": session_id,
            "remaining_credits": new_credits,
            "data_used": user_data is not None
        })
        
    except Exception as e:
        print(f"Start bot error: {e}")
        return jsonify({"error": "Failed to start bot"}), 500

@app.route('/stop_bot', methods=['POST'])
@auth_required
def stop_bot():
    try:
        user = request.user
        
        # Find and stop user's session
        session_found = False
        for session_id, session in list(session_manager.sessions.items()):
            if session.get('user_email') == user['email']:
                session_manager.remove_session(session_id)
                session_found = True
        
        if session_found:
            return jsonify({"status": "success", "message": "Bot stopped successfully"})
        else:
            return jsonify({"error": "No active session found"}), 404
        
    except Exception as e:
        print(f"Stop bot error: {e}")
        return jsonify({"error": "Failed to stop bot"}), 500

@app.route('/get_status', methods=['POST'])
@auth_required
def get_status():
    try:
        user = request.user
        
        session = session_manager.get_user_session(user['email'])
        if session:
            return jsonify({
                "status": "success",
                "bot_status": session.get('status', 'unknown'),
                "started_at": session.get('started_at'),
                "session_id": list(session_manager.sessions.keys())[0] if session_manager.sessions else None
            })
        else:
            return jsonify({"status": "success", "bot_status": "no_active_session"})
        
    except Exception as e:
        print(f"Status error: {e}")
        return jsonify({"error": "Failed to get status"}), 500

def run_bot_for_user(email, user_data, session_id):
    """Run bot for specific user with their data"""
    try:
        print(f"🤖 Starting bot for {email}")
        
        # Update session status
        if session_id in session_manager.sessions:
            session_manager.sessions[session_id]['status'] = 'running'
        
        if user_data:
            phones = user_data.get('phone_numbers', [])
            messages = user_data.get('messages', [])
            
            print(f"📊 Processing {len(phones)} numbers for {email}")
            
            # Simulate processing (replace with actual WhatsApp bot logic)
            for i, phone in enumerate(phones):
                if i < len(messages):
                    print(f"📱 Sending to {phone}: {messages[i][:50]}...")
                    # Simulate work - replace this with actual WhatsApp sending
                    time.sleep(2)
                    
                    # Update status in data
                    statuses = user_data.get('statuses', [])
                    if i < len(statuses):
                        statuses[i] = 'Sent'
                        sheets_manager.save_user_data(email, phones, messages, statuses)
        
        print(f"✅ Bot completed for {email}")
        
        # Update session status
        if session_id in session_manager.sessions:
            session_manager.sessions[session_id]['status'] = 'completed'
        
    except Exception as e:
        print(f"❌ Bot error for {email}: {e}")
        if session_id in session_manager.sessions:
            session_manager.sessions[session_id]['status'] = 'error'

if __name__ == "__main__":
    port = int(os.environ.get('PORT', 10000))
    print(f"🚀 WhatsApp Bot Server starting on port {port}")
    print(f"📊 Master Sheet URL: {Config.MASTER_SHEET_URL}")
    app.run(host="0.0.0.0", port=port, debug=False)