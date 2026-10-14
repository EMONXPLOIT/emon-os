from flask import Flask, render_template, request, jsonify, session
import sqlite3
import json
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "emon_secure_manager_key_2026"

def init_db():
    conn = sqlite3.connect('emon_cloud.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            app_data TEXT DEFAULT '{}'
        )
    ''')
    conn.commit()
    conn.close()

init_db()

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/api/auth', methods=['POST'])
def auth():
    data = request.json
    action = data.get('action')
    email = data.get('email', '').strip().lower()
    password = data.get('password', '')
    name = data.get('name', '').strip()

    conn = sqlite3.connect('emon_cloud.db')
    c = conn.cursor()

    if action == 'signup':
        if not name or not email or not password:
            return jsonify({'status': 'error', 'msg': 'সবগুলো ঘর পূরণ করুন!'})
        hashed_pw = generate_password_hash(password)
        try:
            c.execute("INSERT INTO users (name, email, password, app_data) VALUES (?, ?, ?, ?)",
                      (name, email, hashed_pw, '{}'))
            conn.commit()
            session['user_email'] = email
            session['user_name'] = name
            conn.close()
            return jsonify({'status': 'success', 'name': name, 'email': email, 'data': {}})
        except sqlite3.IntegrityError:
            conn.close()
            return jsonify({'status': 'error', 'msg': 'এই জিমেইল দিয়ে ইতিমধ্যে অ্যাকাউন্ট খোলা হয়েছে!'})

    elif action == 'login':
        c.execute("SELECT name, password, app_data FROM users WHERE email = ?", (email,))
        user = c.fetchone()
        conn.close()
        if user and check_password_hash(user[1], password):
            session['user_email'] = email
            session['user_name'] = user[0]
            saved_data = json.loads(user[2]) if user[2] else {}
            return jsonify({'status': 'success', 'name': user[0], 'email': email, 'data': saved_data})
        else:
            return jsonify({'status': 'error', 'msg': 'ভুল জিমেইল অথবা পাসওয়ার্ড!'})

@app.route('/api/session', methods=['GET'])
def check_session():
    if 'user_email' in session:
        conn = sqlite3.connect('emon_cloud.db')
        c = conn.cursor()
        c.execute("SELECT name, app_data FROM users WHERE email = ?", (session['user_email'],))
        user = c.fetchone()
        conn.close()
        if user:
            return jsonify({'logged_in': True, 'name': user[0], 'email': session['user_email'], 'data': json.loads(user[1] or '{}')})
    return jsonify({'logged_in': False})

@app.route('/api/sync', methods=['POST'])
def sync_data():
    if 'user_email' not in session:
        return jsonify({'status': 'unauthorized'})
    
    app_data = json.dumps(request.json)
    conn = sqlite3.connect('emon_cloud.db')
    c = conn.cursor()
    c.execute("UPDATE users SET app_data = ? WHERE email = ?", (app_data, session['user_email']))
    conn.commit()
    conn.close()
    return jsonify({'status': 'saved'})

@app.route('/api/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'status': 'logged_out'})

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)