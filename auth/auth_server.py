import socket
import threading
import json
import logging
import bcrypt
import secrets
import os
from datetime import datetime, timedelta

HOST = '0.0.0.0'
PORT = 8000  # Changed from 7000
USERS_FILE = 'metadata/users.json'
SESSIONS_FILE = 'metadata/sessions.json'
SESSION_TIMEOUT = 3600


logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(threadName)s - %(message)s')

class AuthServer:
    def __init__(self):
        self.users = {}
        self.sessions = {}
        self.lock = threading.Lock()
        self._load_users()
        self._load_sessions()
    
    def _load_users(self):
        try:
            os.makedirs(os.path.dirname(USERS_FILE), exist_ok=True)
            if os.path.exists(USERS_FILE):
                with open(USERS_FILE, 'r') as f:
                    self.users = json.load(f)
                logging.info(f"Loaded {len(self.users)} users")
        except Exception as e:
            logging.error(f"Error loading users: {e}")
            self.users = {}
    
    def _save_users(self):
        try:
            os.makedirs(os.path.dirname(USERS_FILE), exist_ok=True)
            with open(USERS_FILE, 'w') as f:
                json.dump(self.users, f, indent=4)
        except Exception as e:
            logging.error(f"Error saving users: {e}")
    
    def _load_sessions(self):
        try:
            if os.path.exists(SESSIONS_FILE):
                with open(SESSIONS_FILE, 'r') as f:
                    self.sessions = json.load(f)
                self._clean_expired_sessions()
        except Exception as e:
            logging.error(f"Error loading sessions: {e}")
            self.sessions = {}
    
    def _save_sessions(self):
        try:
            os.makedirs(os.path.dirname(SESSIONS_FILE), exist_ok=True)
            with open(SESSIONS_FILE, 'w') as f:
                json.dump(self.sessions, f, indent=4)
        except Exception as e:
            logging.error(f"Error saving sessions: {e}")
    
    def _clean_expired_sessions(self):
        now = datetime.now().timestamp()
        expired = [token for token, data in self.sessions.items() 
                   if data['expires_at'] < now]
        for token in expired:
            del self.sessions[token]
        if expired:
            self._save_sessions()
    
    def _handle_register(self, payload):
        email = payload.get('email')
        password = payload.get('password')
        name = payload.get('name', email)
        
        if not email or not password:
            return {"status": "error", "message": "Email and password required"}
        
        with self.lock:
            if email in self.users:
                return {"status": "error", "message": "User already exists"}
            
            password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            
            self.users[email] = {
                "password_hash": password_hash.decode('utf-8'),
                "name": name,
                "created_at": datetime.now().isoformat()
            }
            
            self._save_users()
            logging.info(f"New user registered: {email}")
            
            return {"status": "ok", "message": "User registered successfully"}
    
    def _handle_login(self, payload):
        email = payload.get('email')
        password = payload.get('password')
        
        if not email or not password:
            return {"status": "error", "message": "Email and password required"}
        
        with self.lock:
            if email not in self.users:
                return {"status": "error", "message": "Invalid credentials"}
            
            user = self.users[email]
            password_hash = user['password_hash'].encode('utf-8')
            
            if not bcrypt.checkpw(password.encode('utf-8'), password_hash):
                return {"status": "error", "message": "Invalid credentials"}
            
            session_token = secrets.token_urlsafe(32)
            expires_at = (datetime.now() + timedelta(seconds=SESSION_TIMEOUT)).timestamp()
            
            self.sessions[session_token] = {
                "email": email,
                "expires_at": expires_at
            }
            
            self._save_sessions()
            logging.info(f"User logged in: {email}")
            
            return {
                "status": "ok",
                "session_token": session_token,
                "email": email,
                "name": user['name']
            }
    
    def _handle_verify(self, payload):
        session_token = payload.get('session_token')
        
        if not session_token:
            return {"status": "error", "message": "Session token required"}
        
        with self.lock:
            if session_token not in self.sessions:
                return {"status": "error", "message": "Invalid session"}
            
            session = self.sessions[session_token]
            
            if session['expires_at'] < datetime.now().timestamp():
                del self.sessions[session_token]
                self._save_sessions()
                return {"status": "error", "message": "Session expired"}
            
            return {
                "status": "ok",
                "email": session['email']
            }
    
    def _handle_logout(self, payload):
        session_token = payload.get('session_token')
        
        if not session_token:
            return {"status": "error", "message": "Session token required"}
        
        with self.lock:
            if session_token in self.sessions:
                email = self.sessions[session_token]['email']
                del self.sessions[session_token]
                self._save_sessions()
                logging.info(f"User logged out: {email}")
            
            return {"status": "ok", "message": "Logged out successfully"}
    
    def _handle_client(self, client_socket):
        try:
            data = client_socket.recv(4096).decode('utf-8')
            request = json.loads(data)
            command = request.get("command")
            payload = request.get("payload", {})
            
            handler_map = {
                "REGISTER": self._handle_register,
                "LOGIN": self._handle_login,
                "VERIFY": self._handle_verify,
                "LOGOUT": self._handle_logout,
            }
            
            handler = handler_map.get(command)
            if handler:
                response = handler(payload)
            else:
                response = {"status": "error", "message": "Unknown command"}
            
            client_socket.sendall(json.dumps(response).encode('utf-8'))
        except Exception as e:
            logging.error(f"Error handling client: {e}", exc_info=True)
            error_msg = {"status": "error", "message": str(e)}
            client_socket.sendall(json.dumps(error_msg).encode('utf-8'))
        finally:
            client_socket.close()
    
    def start(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((HOST, PORT))
        server_socket.listen(10)
        logging.info(f"Auth Server listening on {HOST}:{PORT}")
        
        while True:
            client_socket, addr = server_socket.accept()
            logging.info(f"Accepted connection from {addr}")
            client_thread = threading.Thread(target=self._handle_client, args=(client_socket,))
            client_thread.start()

if __name__ == "__main__":
    server = AuthServer()
    server.start()
