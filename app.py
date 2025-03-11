from flask import Flask, request, jsonify, session
from flask_cors import CORS
from flask_wtf import csrf
from flask_wtf.csrf import CSRFProtect, generate_csrf
from flask_socketio import SocketIO, emit
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
from cryptography.fernet import Fernet
import sqlite3
import os
import uuid

from Cryptodome.Cipher import AES, PKCS1_OAEP
from Cryptodome.PublicKey import RSA
from Cryptodome.Random import get_random_bytes

app = Flask(__name__)
# Note: For production, do not hardcode secrets. Use environment variables or secure config.
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SESSION_TYPE'] = 'filesystem'
Session(app)
CORS(app, supports_credentials=True)
socketio = SocketIO(app, cors_allowed_origins="*")

# Encryption setup
KEY_FILE_PATH = 'encryption_key.txt'
AES_KEY_FILE_PATH = 'encryption_aes_key.txt'

csrf = CSRFProtect(app)

def generate_or_load_encryption_aes_key():
    if os.path.exists(AES_KEY_FILE_PATH):
        return load_encryption_key()
    else:
        aes_key = get_random_bytes(16)  # Generate a random AES key
        save_encryption_aes_key(aes_key)
        return aes_key

def generate_or_load_encryption_key():
    if os.path.exists(KEY_FILE_PATH):
        return load_encryption_key()
    else:
        key = Fernet.generate_key()
        save_encryption_key(key)
        return key

def load_encryption_key():
    try:
        with open(KEY_FILE_PATH, 'rb') as key_file:
            encryption_key = key_file.read()
        return encryption_key
    except FileNotFoundError:
        print("Encryption key file not found.")
        return None
    except Exception as e:
        print("Error loading encryption key:", e)
        return None

def save_encryption_key(key):
    try:
        with open(KEY_FILE_PATH, 'wb') as key_file:
            key_file.write(key)
        print("Encryption key saved to file:", KEY_FILE_PATH)
    except Exception as e:
        print("Error saving encryption key:", e)

def save_encryption_aes_key(key):
    try:
        with open(AES_KEY_FILE_PATH, 'wb') as key_file:
            key_file.write(key)
        print("Encryption AES key saved to file:", AES_KEY_FILE_PATH)
    except Exception as e:
        print("Error saving encryption key:", e)

aes_key = generate_or_load_encryption_aes_key()
encryption_key = generate_or_load_encryption_key()

if aes_key is None:
    exit(1)
else:
    print("Encryption key loaded/generated successfully:", aes_key)

def generate_rsa_keypair():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

private_key, public_key = generate_rsa_keypair()

def encrypt_with_rsa(public_key, plaintext):
    rsa_key = RSA.import_key(public_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    return cipher_rsa.encrypt(plaintext)

def decrypt_with_rsa(private_key, ciphertext):
    rsa_key = RSA.import_key(private_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    return cipher_rsa.decrypt(ciphertext)

def encrypt_with_aes(key, plaintext):
    cipher_aes = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher_aes.iv + cipher_aes.encrypt(pad(plaintext))
    return ciphertext

def decrypt_with_aes(key, ciphertext):
    iv = ciphertext[:AES.block_size]
    cipher_aes = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher_aes.decrypt(ciphertext[AES.block_size:]))
    return plaintext

encrypted_aes_key = encrypt_with_rsa(public_key, aes_key)
print(encrypted_aes_key)
decrypted_aes_key = decrypt_with_rsa(private_key, encrypted_aes_key)
print(decrypted_aes_key)
print(aes_key)

def pad(s):
    padding_length = AES.block_size - len(s) % AES.block_size
    padding = bytes([padding_length]) * padding_length
    return s + padding

def unpad(s):
    padding_length = s[-1]
    return s[:-padding_length]

def get_db_connection():
    conn = sqlite3.connect('users.db')
    conn.row_factory = sqlite3.Row
    return conn

def create_table():
    conn = get_db_connection()
    c = conn.cursor()
    # Create user and chats tables using parameterized queries where needed.
    c.execute('''CREATE TABLE IF NOT EXISTS user (
                    id INTEGER PRIMARY KEY,
                    username TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL)''')
    c.execute('''CREATE TABLE IF NOT EXISTS chats (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    type TEXT NOT NULL,
                    participants TEXT NOT NULL)''')
    c.execute('''CREATE TABLE IF NOT EXISTS messages (
                    id TEXT PRIMARY KEY,
                    sender TEXT NOT NULL,
                    chat_id TEXT NOT NULL,
                    encrypted_content BLOB NOT NULL,
                    FOREIGN KEY (chat_id) REFERENCES chats (id))''')
    c.execute('''CREATE TABLE IF NOT EXISTS login_attempts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)''')
    c.execute('''CREATE TABLE IF NOT EXISTS events (
                    id TEXT PRIMARY KEY,
                    creator TEXT NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT,
                    event_date DATE NOT NULL,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP)''')
    conn.commit()

    c.execute('SELECT * FROM chats WHERE type = ?', ("global",))
    if not c.fetchone():
        global_chat_id = str(uuid.uuid4())
        c.execute('INSERT INTO chats (id, name, type, participants) VALUES (?, ?, ?, ?)',
                  (global_chat_id, 'Global Chat', 'global', 'all'))
        conn.commit()

    conn.close()

create_table()

# All SQL queries below use parameterized queries.

def check_login_attempts(username):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('''SELECT COUNT(*) as attempt_count
                 FROM login_attempts 
                 WHERE username = ? 
                 AND timestamp >= datetime('now', '-15 minutes')''', (username,))
    attempts = c.fetchone()['attempt_count']
    conn.close()
    return attempts

def record_login_attempt(username):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('INSERT INTO login_attempts (username) VALUES (?)', (username,))
    conn.commit()
    conn.close()

def clear_old_attempts(username):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("DELETE FROM login_attempts WHERE username = ? AND timestamp < datetime('now', '-15 minutes')",
              (username,))
    conn.commit()
    conn.close()

@app.after_request
def set_csrf_cookie(response):
    response.set_cookie('csrf_token', generate_csrf())
    return response

@app.route('/api/messages', methods=['GET'])
def get_messages():
    if 'username' not in session:
        return jsonify({"error": "Unauthorized"}), 401

    chat_id = request.args.get('chat_id')
    conn = get_db_connection()
    c = conn.cursor()
    # Use parameterized query to safely pass chat_id
    c.execute('SELECT * FROM messages WHERE chat_id = ?', (chat_id,))
    messages = c.fetchall()
    conn.close()

    decrypted_messages = []
    for message in messages:
        try:
            decrypted_data = decrypt_with_aes(decrypted_aes_key, message['encrypted_content']).decode()
            decrypted_messages.append(
                {"sender": message['sender'], "chat_id": message['chat_id'], "message": decrypted_data})
        except Exception as e:
            print("Error decrypting message:", e)
    return jsonify(decrypted_messages)

@app.route('/api/login', methods=['POST'])
@csrf.exempt
def login():
    data = request.json
    username = data['username']
    password = data['password']

    clear_old_attempts(username)
    attempts = check_login_attempts(username)
    if attempts >= 3:
        return jsonify({"error": "Too many failed login attempts. Please try again after 15 minutes."}), 403

    if verify_user(username, password):
        session['username'] = username
        return jsonify({"success": "Logged in"})
    else:
        record_login_attempt(username)
        return jsonify({"error": "Invalid username or password"}), 401

@app.route('/api/register', methods=['POST'])
def register():
    data = request.json
    username = data['username']
    password = data['password']
    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400
    elif user_exists(username):
        return jsonify({"error": "Username already exists"}), 409
    else:
        add_user(username, password)
        return jsonify({"success": "Registration successful"})

@app.route('/api/logout', methods=['POST'])
def logout():
    session.pop('username', None)
    return jsonify({"success": "Logged out"})

@app.route('/api/users', methods=['GET'])
def get_users():
    if 'username' not in session:
        return jsonify({"error": "Unauthorized"}), 401
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT username FROM user")
    users = c.fetchall()
    conn.close()
    return jsonify([user['username'] for user in users])

@app.route('/api/chats', methods=['POST'])
def create_chat():
    if 'username' not in session:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.json
    name = data['name']
    chat_type = data['type']
    participants = data.get('participants', [])

    username = session['username']
    if username not in participants:
        participants.append(username)

    if not name or not chat_type or not participants:
        return jsonify({"error": "Chat name, type, and participants are required"}), 400

    participants_str = ','.join(participants)
    chat_id = str(uuid.uuid4())

    conn = get_db_connection()
    c = conn.cursor()
    c.execute('INSERT INTO chats (id, name, type, participants) VALUES (?, ?, ?, ?)',
              (chat_id, name, chat_type, participants_str))
    conn.commit()
    conn.close()

    return jsonify({"chat_id": chat_id})

@app.route('/api/chats', methods=['GET'])
def get_chats():
    if 'username' not in session:
        return jsonify({"error": "Unauthorized"}), 401

    username = session['username']
    conn = get_db_connection()
    c = conn.cursor()
    # For LIKE queries, build the pattern and pass it as a parameter.
    like_pattern = "%" + username + "%"
    c.execute('SELECT * FROM chats WHERE type = ? OR participants LIKE ?', ("global", like_pattern))
    chats = c.fetchall()
    conn.close()

    return jsonify([dict(chat) for chat in chats])

@app.route('/api/create_private_chat', methods=['POST'])
def create_private_chat():
    if 'username' not in session:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.json
    participant = data['participant']

    if not participant:
        return jsonify({"error": "Participant username is required"}), 400

    username = session['username']
    participants = sorted([username, participant])

    chat_name = f"Private chat between {participants[0]} and {participants[1]}"
    chat_id = str(uuid.uuid4())

    conn = get_db_connection()
    c = conn.cursor()
    c.execute('INSERT INTO chats (id, name, type, participants) VALUES (?, ?, ?, ?)',
              (chat_id, chat_name, 'private', ','.join(participants)))
    conn.commit()
    conn.close()

    return jsonify({"chat_id": chat_id, "chat_name": chat_name})

@app.route('/api/clear_chat', methods=['POST'])
def clear_chat():
    if 'username' not in session:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.json
    chat_id = data['chat_id']

    if not chat_id:
        return jsonify({"error": "Chat ID is required"}), 400

    conn = get_db_connection()
    c = conn.cursor()

    # Delete messages associated with the chat using a parameterized query.
    c.execute('DELETE FROM messages WHERE chat_id = ?', (chat_id,))
    # Delete the chat entry.
    c.execute('DELETE FROM chats WHERE id = ?', (chat_id,))
    conn.commit()
    conn.close()

    return jsonify({"success": "Chat cleared"})

@app.route('/api/events', methods=['POST'])
def create_event():
    if 'username' not in session:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.json
    title = data['title']
    description = data.get('description')
    event_date = data['event_date']
    creator = session['username']

    if not title or not event_date:
        return jsonify({"error": "Title and event date are required"}), 400

    event_id = str(uuid.uuid4())
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('INSERT INTO events (id, creator, title, description, event_date) VALUES (?, ?, ?, ?, ?)',
              (event_id, creator, title, description, event_date))
    conn.commit()
    conn.close()

    return jsonify({"success": "Event created", "event_id": event_id})

@app.route('/api/events', methods=['GET'])
def get_events():
    if 'username' not in session:
        return jsonify({"error": "Unauthorized"}), 401

    conn = get_db_connection()
    c = conn.cursor()
    c.execute('SELECT * FROM events')
    events = c.fetchall()
    conn.close()

    return jsonify([dict(event) for event in events])

@app.route('/api/events/<event_id>', methods=['DELETE'])
def delete_event(event_id):
    if 'username' not in session:
        return jsonify({"error": "Unauthorized"}), 401

    conn = get_db_connection()
    c = conn.cursor()
    c.execute('DELETE FROM events WHERE id = ?', (event_id,))
    conn.commit()
    conn.close()

    return jsonify({"success": "Event deleted"})

@socketio.on('connect')
def handle_connect():
    if 'username' in session:
        app.logger.debug(f"User {session['username']} connected.")
    else:
        app.logger.debug("Anonymous user connected.")

@socketio.on('message')
def handle_message(data):
    if 'username' not in session:
        app.logger.debug(f"Unauthorized message attempt. Session: {session}")
        emit('message', {'error': 'Unauthorized'}, room=request.sid)
        return

    username = session['username']
    chat_id = data.get('chat_id')
    message_content = data.get('message')

    if not chat_id or not message_content:
        emit('message', {'error': 'Invalid data'}, room=request.sid)
        return

    # Encrypt the message using AES.
    encrypted_data = encrypt_with_aes(decrypted_aes_key, message_content.encode())
    insert_message(username, chat_id, encrypted_data)
    emit('message', {'sender': username, 'chat_id': chat_id, 'message': message_content}, broadcast=True)

def insert_message(sender, chat_id, encrypted_content):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("INSERT INTO messages (id, sender, chat_id, encrypted_content) VALUES (?, ?, ?, ?)",
              (str(uuid.uuid4()), sender, chat_id, encrypted_content))
    conn.commit()
    conn.close()

def verify_user(username, password):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT password FROM user WHERE username = ?", (username,))
    user = c.fetchone()
    conn.close()
    if user and check_password_hash(user['password'], password):
        return True
    return False

def user_exists(username):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT username FROM user WHERE username = ?", (username,))
    user = c.fetchone()
    conn.close()
    return user is not None

def add_user(username, password):
    hashed_password = generate_password_hash(password)
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("INSERT INTO user (username, password) VALUES (?, ?)", (username, hashed_password))
    conn.commit()
    conn.close()

if __name__ == '__main__':
    socketio.run(app, debug=True)
