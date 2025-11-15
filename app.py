from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
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

app = Flask(__name__, static_folder='.', static_url_path='')
CORS(app)

# Configuration with environment variables
class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'whatsapp-bulk-bot-2024-secret-key-12345')
    MASTER_SHEET_URL = os.environ.get('MASTER_SHEET_URL', 'https://docs.google.com/spreadsheets/d/1YOUR_SHEET_ID_HERE/edit')
    
    # Get credentials from environment variables
    GOOGLE_CREDENTIALS = {
        "type": "service_account",
        "project_id": os.environ.get('GOOGLE_PROJECT_ID', 'whatsappbot-478316'),
        "private_key_id": os.environ.get('GOOGLE_PRIVATE_KEY_ID', 'dbe15e026c07ac87162b6f51e29dc65c04b38aaf'),
        "private_key": os.environ.get('GOOGLE_PRIVATE_KEY', '').replace('\\n', '\n'),
        "client_email": os.environ.get('GOOGLE_CLIENT_EMAIL', 'whatsapp-bot-service@whatsappbot-478316.iam.gserviceaccount.com'),
        "client_id": os.environ.get('GOOGLE_CLIENT_ID', '112647679419855179779'),
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": "https://oauth2.googleapis.com/token",
        "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
        "client_x509_cert_url": os.environ.get('GOOGLE_CLIENT_X509_CERT_URL', 'https://www.googleapis.com/robot/v1/metadata/x509/whatsapp-bot-service%40whatsappbot-478316.iam.gserviceaccount.com'),
        "universe_domain": "googleapis.com"
    }

# Google Sheets Manager
class GoogleSheetsManager:
    def __init__(self):
        self.client = None
        self.master_sheet = None
        self.initialize_sheets()
    
    def initialize_sheets(self):
        try:
            # Check if private key is available
            if not Config.GOOGLE_CREDENTIALS['private_key']:
                print("❌ Google Private Key not found in environment variables")
                return
                
            creds = service_account.Credentials.from_service_account_info(
                Config.GOOGLE_CREDENTIALS,
                scopes=['https://www.googleapis.com/auth/spreadsheets']
            )
            self.client = gspread.authorize(creds)
            self.master_sheet = self.client.open_by_url(Config.MASTER_SHEET_URL)
            print("✅ Google Sheets connected successfully!")
        except Exception as e:
            print(f"❌ Google Sheets error: {e}")
    
    def user_exists(self, email):
        try:
            if not self.master_sheet:
                return False
                
            users_sheet = self.master_sheet.worksheet("users")
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
            if not self.master_sheet:
                return None
                
            users_sheet = self.master_sheet.worksheet("users")
            secret_key = f"sk_{secrets.token_hex(16)}"
            
            users_sheet.append_row([
                email.lower(),
                hashlib.sha256(password.encode()).hexdigest(),
                secret_key,
                100,
                "active",
                datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            ])
            
            return secret_key
        except Exception as e:
            print(f"Error creating user: {e}")
            return None
    
    def authenticate_user(self, email, password):
        try:
            if not self.master_sheet:
                return None
                
            users_sheet = self.master_sheet.worksheet("users")
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

# Initialize sheets manager
sheets_manager = GoogleSheetsManager()

# Simple session storage
user_sessions = {}

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
        "sheets_connected": sheets_manager.client is not None,
        "timestamp": datetime.now().isoformat()
    })

@app.route('/register', methods=['POST'])
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
        
        if not sheets_manager.master_sheet:
            return jsonify({"error": "Google Sheets not connected. Please check configuration."}), 500
        
        if sheets_manager.user_exists(email):
            return jsonify({"error": "Email already registered"}), 400
        
        secret_key = sheets_manager.create_user(email, password)
        
        if not secret_key:
            return jsonify({"error": "Registration failed. Please try again."}), 500
        
        return jsonify({
            "status": "success",
            "message": "Registration successful!",
            "secret_key": secret_key
        })
        
    except Exception as e:
        print(f"Registration error: {e}")
        return jsonify({"error": "Registration failed"}), 500

@app.route('/login', methods=['POST'])
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
        
        return jsonify({
            "status": "success",
            "message": "Login successful",
            "secret_key": user['secret_key'],
            "credits": user.get('credits', 100)
        })
            
    except Exception as e:
        print(f"Login error: {e}")
        return jsonify({"error": "Login failed"}), 500

@app.route('/demo_register', methods=['POST'])
def demo_register():
    """Demo endpoint that works without Google Sheets"""
    try:
        data = request.get_json()
        email = data.get('email', '').strip().lower()
        password = data.get('password')
        
        if not email or not password:
            return jsonify({"error": "Email and password are required"}), 400
        
        # Generate demo secret key
        secret_key = f"demo_sk_{secrets.token_hex(8)}"
        
        return jsonify({
            "status": "success", 
            "message": "DEMO MODE: Registration successful!",
            "secret_key": secret_key,
            "demo_mode": True
        })
    except Exception as e:
        return jsonify({"error": "Demo registration failed"}), 500

if __name__ == "__main__":
    port = int(os.environ.get('PORT', 10000))
    print(f"🚀 WhatsApp Bot Server starting on port {port}")
    app.run(host="0.0.0.0", port=port, debug=False)
