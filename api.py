from flask import Flask, request, jsonify
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
DATABASE = 'database.db'

def init_db():
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            code TEXT NOT NULL UNIQUE,
                            password TEXT NOT NULL
                          )''')
        conn.commit()

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    code = data.get('code')
    password = data.get('password')
    
    if not code or not password:
        return jsonify({'message': 'Code and password are required!'}), 400
    
    hashed_password = generate_password_hash(password)
    
    try:
        with sqlite3.connect(DATABASE) as conn:
            cursor = conn.cursor()
            cursor.execute('INSERT INTO users (code, password) VALUES (?, ?)', (code, hashed_password))
            conn.commit()
        return jsonify({'message': 'User registered successfully!'}), 201
    except sqlite3.IntegrityError:
        return jsonify({'message': 'Code already exists!'}), 409

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    code = data.get('code')
    password = data.get('password')
    
    if not code or not password:
        return jsonify({'message': 'Code and password are required!'}), 400
    
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT password FROM users WHERE code = ?', (code,))
        user = cursor.fetchone()
    
    if user and check_password_hash(user[0], password):
        return jsonify({'message': 'Logged in successfully!'}), 200
    else:
        return jsonify({'message': 'Invalid code or password!'}), 401

if __name__ == '__main__':
    init_db()  # Initialize the database here
    app.run(debug=True)
