from flask import Flask, request, jsonify, render_template
import sqlite3
import hashlib
import datetime
from config import AppConfig
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

def get_db():
    return sqlite3.connect(AppConfig.DATABASE_PATH)

@app.route('/')
def index_route():
    return render_template("index.html")

@app.route('/api/auth/login', methods=['POST'])
def login():
    try:
        data = request.json
        username = data.get('username')
        password = data.get('password')
        
        db = get_db()
        cursor = db.cursor()
        try:
            cursor.execute('SELECT id, username, password_hash FROM users WHERE username = ?', (username,))
            user_data = cursor.fetchone()
            if user_data and check_password_hash(user_data[2], password):
                user = (user_data[0], user_data[1])
            else:
                user = None
        finally:
            cursor.close()
            db.close()
        
        if user:
            return jsonify({'token': 'mock-token', 'success': True})
        else:
            return jsonify({'error': 'Invalid credentials'}), 401
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/auth/register', methods=['POST'])
def register():
    try:
        data = request.json
        full_name = data.get('full_name')
        date_of_birth = data.get('date_of_birth')
        email = data.get('email')
        username = data.get('username')
        password = data.get('password')

        if not all([full_name, date_of_birth, email, username, password]):
            return jsonify({"success": False, "error": "All fields required"}), 400

        system_email = f"@{username}@R3ÆLƎRAI.com"
        password_hash = generate_password_hash(password, method='scrypt:32768:8:1', salt_length=32)

        db = get_db()
        cursor = db.cursor()
        try:
            cursor.execute('SELECT id FROM users WHERE username = ?', (username,))
            if cursor.fetchone():
                return jsonify({"success": False, "error": "Username already exists"}), 400

            cursor.execute('INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)', (username, password_hash, email))
            db.commit()
        finally:
            cursor.close()
            db.close()

        return jsonify({"success": True, "username": username, "system_email": system_email})

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

if __name__ == "__main__":
    import os
    debug_mode = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    app.run(host="0.0.0.0", port=5000, debug=debug_mode)
