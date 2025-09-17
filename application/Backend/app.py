
from flask import Flask, request, jsonify, render_template
import sqlite3
import hashlib
import datetime
import sys
import os
from config import AppConfig

# Add AI Core to path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', 'AI_Core_Worker'))
sys.path.append(os.path.dirname(__file__))
from ai_core_worker import RealerAI

app = Flask(__name__)

def get_db():
    return sqlite3.connect(AppConfig.DATABASE_PATH)

# Initialize AI Core with optional OpenAI integration
openai_api_key = os.environ.get("OPENAI_API_KEY")
ai_core = RealerAI(AppConfig, get_db, openai_api_key)

@app.route('/')
def index_route():
    return render_template("index.html")

@app.route('/api/auth/login', methods=['POST'])
def login():
    try:
        data = request.json
        username = data.get('username')
        password = data.get('password')
        
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        
        db = get_db()
        cursor = db.cursor()
        try:
            cursor.execute('SELECT id, username FROM users WHERE username = ? AND password_hash = ?', (username, password_hash))
            user = cursor.fetchone()
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
        password_hash = hashlib.sha256(password.encode()).hexdigest()

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

@app.route('/api/chat', methods=['POST'])
def chat():
    try:
        data = request.json
        message = data.get('message', '')
        voice_enabled = data.get('voice_enabled', False)
        user_id = data.get('user_id', 'anonymous')
        conversation_history = data.get('conversation_history', [])
        
        if not message.strip():
            return jsonify({"error": "Message cannot be empty"}), 400
        
        # Process message through enhanced AI Core with conversation context
        response = ai_core.process_chat(message, user_id, conversation_history)
        
        # Get updated conversation context for frontend
        recent_history = ai_core.get_conversation_history(user_id, 3) if user_id != 'anonymous' else []
        
        return jsonify({
            "response": response,
            "voice_enabled": voice_enabled,
            "adaptability_level": ai_core.adaptability_level,
            "conversation_context": len(recent_history),
            "processing_mode": "dynamic_contextual"
        })
    except Exception as e:
        return jsonify({"error": f"AI processing error: {str(e)}"}), 500

@app.route('/api/generate-code', methods=['POST'])
def generate_code():
    try:
        data = request.json
        language = data.get('language', '')
        task = data.get('task', '')
        requirements = data.get('requirements', '')
        
        if not language or not task:
            return jsonify({"error": "Language and task are required"}), 400
        
        result = ai_core.generate_code_with_ai(language, task, requirements)
        return jsonify(result)
        
    except Exception as e:
        return jsonify({"error": f"Code generation error: {str(e)}"}), 500

@app.route('/api/forensic-analysis', methods=['POST'])
def forensic_analysis():
    try:
        data = request.json
        file_info = data.get('file_info', '')
        analysis_type = data.get('analysis_type', '')
        
        if not file_info or not analysis_type:
            return jsonify({"error": "File info and analysis type are required"}), 400
        
        result = ai_core.analyze_forensics_with_ai(file_info, analysis_type)
        return jsonify(result)
        
    except Exception as e:
        return jsonify({"error": f"Forensic analysis error: {str(e)}"}), 500

@app.route('/api/ai-status', methods=['GET'])
def ai_status():
    return jsonify({
        "openai_available": bool(ai_core.openai_integration),
        "adaptability_level": ai_core.adaptability_level,
        "total_insights": len(ai_core.insights),
        "knowledge_sources": len(ai_core.heart.get_db() if hasattr(ai_core.heart, 'get_db') else [])
    })

if __name__ == "__main__":
    debug_mode = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    app.run(host="0.0.0.0", port=5000, debug=debug_mode)