# api/admin.py - ADMIN PANEL API
from http.server import BaseHTTPRequestHandler
import json, time, hashlib, secrets
from datetime import datetime, timezone

# ============================================
# ADMIN DATABASE (In-memory - for production use real DB!)
# ============================================
# Admin configuration
ADMIN_CONFIG = {
    'password': 'admin12345',  # CHANGE THIS!
    'webhook_url': '',         # Global webhook (optional)
    'site_title': 'Robin Cookie Checker Pro'
}

# User database
USER_DB = {
    # Format: username: {password_hash, expiry, created, plan, active}
    'demo_user': {
        'password_hash': hash_password('demo123'),
        'expiry': time.time() + 86400 * 30,  # 30 days
        'created': time.time(),
        'plan': 'premium',
        'active': True,
        'last_login': None
    }
}

# Session tokens (for authentication)
SESSIONS = {}

# ============================================
# HELPER FUNCTIONS
# ============================================
def hash_password(password):
    """Simple password hashing (use bcrypt in production)"""
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(stored_hash, password):
    """Verify password against stored hash"""
    return stored_hash == hash_password(password)

def generate_token():
    """Generate random session token"""
    return secrets.token_urlsafe(32)

def require_admin_auth(handler):
    """Middleware to require admin authentication"""
    auth_header = handler.headers.get('Authorization', '')
    
    if not auth_header.startswith('Bearer '):
        return False
    
    token = auth_header[7:]
    return token in SESSIONS and SESSIONS[token].get('role') == 'admin'

def require_user_auth(handler):
    """Middleware to require user authentication"""
    auth_header = handler.headers.get('Authorization', '')
    
    if not auth_header.startswith('Bearer '):
        return False
    
    token = auth_header[7:]
    if token not in SESSIONS:
        return False
    
    user_data = SESSIONS[token]
    username = user_data.get('username')
    
    # Check if user exists and is active
    if username not in USER_DB:
        return False
    
    user = USER_DB[username]
    
    # Check if account expired
    if user['expiry'] < time.time():
        user['active'] = False
        return False
    
    return True

# ============================================
# HTTP HANDLER CLASS
# ============================================
class handler(BaseHTTPRequestHandler):
    
    def do_OPTIONS(self):
        """Handle CORS preflight"""
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'POST, GET, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        self.end_headers()
    
    def do_GET(self):
        """Handle GET requests"""
        path = self.path
        
        if path == '/api/admin/login':
            # Return admin login page status
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            
            self.wfile.write(json.dumps({
                'success': True,
                'site_title': ADMIN_CONFIG['site_title'],
                'api_version': '1.0'
            }).encode())
            
        elif path == '/api/admin/dashboard':
            # Admin dashboard data
            if not require_admin_auth(self):
                self.send_unauthorized()
                return
            
            # Calculate statistics
            active_users = sum(1 for u in USER_DB.values() if u['active'] and u['expiry'] > time.time())
            expired_users = sum(1 for u in USER_DB.values() if not u['active'] or u['expiry'] <= time.time())
            total_robux = 0  # You can track this if you store checking results
            
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            
            self.wfile.write(json.dumps({
                'success': True,
                'stats': {
                    'total_users': len(USER_DB),
                    'active_users': active_users,
                    'expired_users': expired_users,
                    'today_logins': sum(1 for s in SESSIONS.values() 
                                      if s.get('login_time', 0) > time.time() - 86400),
                    'memory_usage': len(str(USER_DB)) + len(str(SESSIONS))
                },
                'config': {
                    'site_title': ADMIN_CONFIG['site_title'],
                    'webhook_enabled': bool(ADMIN_CONFIG['webhook_url'])
                }
            }).encode())
            
        elif path == '/api/admin/users':
            # Get user list
            if not require_admin_auth(self):
                self.send_unauthorized()
                return
            
            users_list = []
            for username, data in USER_DB.items():
                days_left = max(0, int((data['expiry'] - time.time()) / 86400))
                
                users_list.append({
                    'username': username,
                    'plan': data.get('plan', 'basic'),
                    'active': data['active'] and data['expiry'] > time.time(),
                    'created': data['created'],
                    'created_date': datetime.fromtimestamp(data['created']).strftime('%Y-%m-%d'),
                    'expiry': data['expiry'],
                    'expiry_date': datetime.fromtimestamp(data['expiry']).strftime('%Y-%m-%d'),
                    'days_left': days_left,
                    'last_login': data.get('last_login'),
                    'last_login_date': datetime.fromtimestamp(data['last_login']).strftime('%Y-%m-%d %H:%M') 
                                     if data.get('last_login') else 'Never'
                })
            
            # Sort by expiry date
            users_list.sort(key=lambda x: x['expiry'])
            
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            
            self.wfile.write(json.dumps({
                'success': True,
                'users': users_list,
                'total': len(users_list)
            }).encode())
            
        else:
            self.send_response(404)
            self.end_headers()
    
    def do_POST(self):
        """Handle POST requests"""
        path = self.path
        
        if path == '/api/admin/login':
            # Admin login
            try:
                content_length = int(self.headers['Content-Length'])
                post_data = self.rfile.read(content_length)
                data = json.loads(post_data)
                
                username = data.get('username', '').strip().lower()
                password = data.get('password', '')
                
                # Check admin credentials
                if username == 'admin' and password == ADMIN_CONFIG['password']:
                    # Generate session token
                    token = generate_token()
                    SESSIONS[token] = {
                        'username': 'admin',
                        'role': 'admin',
                        'login_time': time.time(),
                        'expiry': time.time() + 86400  # 24 hours
                    }
                    
                    self.send_response(200)
                    self.send_header('Content-type', 'application/json')
                    self.send_header('Access-Control-Allow-Origin', '*')
                    self.end_headers()
                    
                    self.wfile.write(json.dumps({
                        'success': True,
                        'message': 'Login successful',
                        'token': token,
                        'user': {
                            'username': 'admin',
                            'role': 'admin',
                            'site_title': ADMIN_CONFIG['site_title']
                        }
                    }).encode())
                else:
                    self.send_unauthorized('Invalid credentials')
                    
            except Exception as e:
                self.send_error(str(e))
                
        elif path == '/api/admin/create_user':
            # Create new user
            if not require_admin_auth(self):
                self.send_unauthorized()
                return
            
            try:
                content_length = int(self.headers['Content-Length'])
                post_data = self.rfile.read(content_length)
                data = json.loads(post_data)
                
                username = data.get('username', '').strip().lower()
                password = data.get('password', '')
                days = int(data.get('days', 30))
                plan = data.get('plan', 'basic')
                
                # Validation
                if not username or not password:
                    self.send_error('Username and password required')
                    return
                
                if len(username) < 3:
                    self.send_error('Username must be at least 3 characters')
                    return
                
                if len(password) < 4:
                    self.send_error('Password must be at least 4 characters')
                    return
                
                if username in USER_DB:
                    self.send_error('Username already exists')
                    return
                
                # Create user
                expiry_time = time.time() + (days * 86400)
                
                USER_DB[username] = {
                    'password_hash': hash_password(password),
                    'expiry': expiry_time,
                    'created': time.time(),
                    'plan': plan,
                    'active': True,
                    'last_login': None
                }
                
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                
                self.wfile.write(json.dumps({
                    'success': True,
                    'message': f'User {username} created successfully',
                    'user': {
                        'username': username,
                        'plan': plan,
                        'expiry': expiry_time,
                        'expiry_date': datetime.fromtimestamp(expiry_time).strftime('%Y-%m-%d %H:%M:%S'),
                        'days': days
                    }
                }).encode())
                
            except Exception as e:
                self.send_error(str(e))
                
        elif path == '/api/admin/delete_user':
            # Delete user
            if not require_admin_auth(self):
                self.send_unauthorized()
                return
            
            try:
                content_length = int(self.headers['Content-Length'])
                post_data = self.rfile.read(content_length)
                data = json.loads(post_data)
                
                username = data.get('username', '').strip().lower()
                
                if username not in USER_DB:
                    self.send_error('User not found')
                    return
                
                # Don't allow deleting admin
                if username == 'admin':
                    self.send_error('Cannot delete admin user')
                    return
                
                # Remove user
                del USER_DB[username]
                
                # Remove user's sessions
                tokens_to_remove = []
                for token, session in SESSIONS.items():
                    if session.get('username') == username:
                        tokens_to_remove.append(token)
                
                for token in tokens_to_remove:
                    del SESSIONS[token]
                
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                
                self.wfile.write(json.dumps({
                    'success': True,
                    'message': f'User {username} deleted successfully'
                }).encode())
                
            except Exception as e:
                self.send_error(str(e))
                
        elif path == '/api/admin/renew_user':
            # Renew user subscription
            if not require_admin_auth(self):
                self.send_unauthorized()
                return
            
            try:
                content_length = int(self.headers['Content-Length'])
                post_data = self.rfile.read(content_length)
                data = json.loads(post_data)
                
                username = data.get('username', '').strip().lower()
                days = int(data.get('days', 30))
                
                if username not in USER_DB:
                    self.send_error('User not found')
                    return
                
                user = USER_DB[username]
                
                # Calculate new expiry
                current_time = time.time()
                current_expiry = user['expiry']
                
                if current_expiry < current_time:
                    current_expiry = current_time
                
                new_expiry = current_expiry + (days * 86400)
                user['expiry'] = new_expiry
                user['active'] = True
                
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                
                self.wfile.write(json.dumps({
                    'success': True,
                    'message': f'User {username} renewed for {days} days',
                    'user': {
                        'username': username,
                        'new_expiry': new_expiry,
                        'new_expiry_date': datetime.fromtimestamp(new_expiry).strftime('%Y-%m-%d %H:%M:%S'),
                        'days_added': days
                    }
                }).encode())
                
            except Exception as e:
                self.send_error(str(e))
                
        elif path == '/api/admin/update_config':
            # Update admin configuration
            if not require_admin_auth(self):
                self.send_unauthorized()
                return
            
            try:
                content_length = int(self.headers['Content-Length'])
                post_data = self.rfile.read(content_length)
                data = json.loads(post_data)
                
                # Update config values
                if 'site_title' in data:
                    ADMIN_CONFIG['site_title'] = data['site_title']
                
                if 'webhook_url' in data:
                    ADMIN_CONFIG['webhook_url'] = data['webhook_url']
                
                if 'admin_password' in data and data['admin_password']:
                    # In production, ask for old password too!
                    ADMIN_CONFIG['password'] = data['admin_password']
                
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                
                self.wfile.write(json.dumps({
                    'success': True,
                    'message': 'Configuration updated successfully',
                    'config': {
                        'site_title': ADMIN_CONFIG['site_title'],
                        'webhook_enabled': bool(ADMIN_CONFIG['webhook_url'])
                    }
                }).encode())
                
            except Exception as e:
                self.send_error(str(e))
                
        elif path == '/api/admin/logout':
            # Logout admin
            auth_header = self.headers.get('Authorization', '')
            
            if auth_header.startswith('Bearer '):
                token = auth_header[7:]
                if token in SESSIONS:
                    del SESSIONS[token]
            
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            
            self.wfile.write(json.dumps({
                'success': True,
                'message': 'Logged out successfully'
            }).encode())
            
        else:
            self.send_response(404)
            self.end_headers()
    
    def send_error(self, message, status_code=400):
        """Send error response"""
        self.send_response(status_code)
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        
        self.wfile.write(json.dumps({
            'success': False,
            'error': message
        }).encode())
    
    def send_unauthorized(self, message='Unauthorized'):
        """Send unauthorized response"""
        self.send_response(401)
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        
        self.wfile.write(json.dumps({
            'success': False,
            'error': message
        }).encode())

# ============================================
# INITIALIZATION
# ============================================
print("[ADMIN API] Admin panel API initialized")
print(f"[ADMIN API] Total users in database: {len(USER_DB)}")