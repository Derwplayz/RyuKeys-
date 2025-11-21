import os, json, random, string, time
from markupsafe import Markup, escape
from datetime import datetime, timedelta, timezone
from flask import Flask, session, redirect, url_for, render_template, request, jsonify, send_file
from werkzeug.middleware.proxy_fix import ProxyFix
import secrets
import hashlib
import io
import csv
import requests
from urllib.parse import urlparse

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'fallback-secret-change-this')

DATA_DIR = "data"
os.makedirs(DATA_DIR, exist_ok=True)
CODES_FILE = os.path.join(DATA_DIR, "codes.json")
PREMIUM_CODES_FILE = os.path.join(DATA_DIR, "premium_keys.json")
ULTRA_CODES_FILE = os.path.join(DATA_DIR, "ultra_keys.json")
ZEROAD_CODES_FILE = os.path.join(DATA_DIR, "zeroad_codes.json")

ADMIN_PASSWORD = "drew"
ADMIN_SESSION_KEY = "admin_logged_in"

VALID_DOMAINS = {
    "lootlabs": ["loot-link.com", "lootdest.org", "lootlabs.io"],
    "linkvertise": ["link-hub.net", "direct-link.net", "link-target.net", "linkvertise.com", "upvert.io"]
}

# Discord OAuth Configuration - USING WORKING CONFIG
DISCORD_CLIENT_ID = "1391860994082472009"
DISCORD_CLIENT_SECRET = "q5PD-1vYrbJl_1cmZTzwm-_PDqNBJy6q"
DISCORD_REDIRECT_URI = "http://localhost:8080/discord/callback"
DISCORD_BOT_TOKEN = "MTM5MjU3NTcwNjcwNTQyODYwMg.GCkoPh.8frtokLNmJmoW5YO9k1cAhAtJ5AKrE3EASbvlw"
DISCORD_GUILD_ID = "1391817979754319902"

# Discord Role IDs - UPDATED WITH CORRECT FORMAT
DISCORD_ROLE_IDS = {
    # Tier Roles (users should only have ONE of these)
    "free": ["1391839228458958889"],        # Free tier role
    "boost": ["1404627044960309329"],       # Boost tier role  
    "premium": ["1391833734461919483"],     # Premium tier role
    "pro": ["1428920662852108441"],         # Pro tier role
    
    # Special Permission Roles (can be combined with tier roles)
    "no_cooldown": ["1428453528464265277"], # No cooldown perk
    "admin": ["1391833880004136970", "1391833838593773820", "1408538388373573854", "1407601837728858174"],
    
    # Server Member Role (everyone should have this)
    "member": ["1418391115714924665"]
}

# Service Access by Tier
TIER_SERVICES = {
    "free": ["roblox", "minecraft", "discord", "outlook"],
    "boost": ["roblox", "minecraft", "discord", "outlook"],
    "premium": ["roblox", "minecraft", "discord", "outlook"],
    "pro": ["roblox", "minecraft", "discord", "outlook", "RobloxFresh"],
    "none": []  # No access
}

# Stock configuration
STOCK_FOLDERS = {
    "free": "stock/free",
    "boost": "stock/boost", 
    "premium": "stock/premium",
    "pro": "stock/pro"
}

SERVICE_FILES = {
    "roblox": {
        "free": "stock/free/roblox.txt",
        "boost": "stock/boost/roblox.txt", 
        "premium": "stock/premium/roblox.txt"
    },
    "minecraft": {
        "free": "stock/free/minecraft.txt",
        "boost": "stock/boost/minecraft.txt", 
        "premium": "stock/premium/minecraft.txt"
    },
    "discord": {
        "free": "stock/free/discord.txt",
        "boost": "stock/boost/discord.txt", 
        "premium": "stock/premium/discord.txt"
    },
    "outlook": {
        "free": "stock/free/outlook.txt"
    },
    "RobloxFresh": {
        "pro": "stock/pro/FRbolox.txt"
    }
}

COOLDOWN_TIMES = {
    "free": 300,    # 5 minutes
    "boost": 180,   # 3 minutes  
    "premium": 60,  # 1 minute
    "pro": 30       # 30 seconds
}

# ------------- Discord OAuth Helpers -----------------
class DiscordAuth:
    def __init__(self):
        self.client_id = DISCORD_CLIENT_ID
        self.client_secret = DISCORD_CLIENT_SECRET
        self.redirect_uri = DISCORD_REDIRECT_URI
        self.bot_token = DISCORD_BOT_TOKEN
        self.guild_id = DISCORD_GUILD_ID
        
        self.api_base = 'https://discord.com/api/v10'
        self.auth_url = f'https://discord.com/api/oauth2/authorize?client_id={self.client_id}&redirect_uri={self.redirect_uri}&response_type=code&scope=identify%20guilds'
        
        self.role_ids = DISCORD_ROLE_IDS

    def get_auth_url(self):
        return self.auth_url

    def get_access_token(self, code):
        data = {
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': self.redirect_uri,
            'scope': 'identify guilds'
        }
        
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        
        response = requests.post(f'{self.api_base}/oauth2/token', data=data, headers=headers)
        print(f"DEBUG: Token response status: {response.status_code}")
        print(f"DEBUG: Token response: {response.text}")
        
        if response.status_code == 200:
            return response.json().get('access_token')
        return None

    def get_user_data(self, access_token):
        """Get user data and roles using the working method from the provided example"""
        # Get the logged-in user's info
        user_headers = {
            'Authorization': f'Bearer {access_token}'
        }
        user_response = requests.get(f'{self.api_base}/users/@me', headers=user_headers)
        print(f"DEBUG: User response status: {user_response.status_code}")
        
        if user_response.status_code != 200:
            print(f"DEBUG: Failed to get user data: {user_response.text}")
            return None
            
        user_data = user_response.json()
        user_id = user_data['id']
        print(f"DEBUG: User data: {user_data}")
        
        # Get the user's member data in the guild using bot token (WORKING METHOD)
        bot_headers = {
            'Authorization': f'Bot {self.bot_token}'
        }
        member_response = requests.get(f'{self.api_base}/guilds/{self.guild_id}/members/{user_id}', headers=bot_headers)
        print(f"DEBUG: Member response status: {member_response.status_code}")
        
        user_roles = []
        if member_response.status_code == 200:
            member_data = member_response.json()
            user_roles = member_data.get('roles', [])
            print(f"DEBUG: Member data: {member_data}")
            print(f"DEBUG: User roles: {user_roles}")
        else:
            print(f"DEBUG: Failed to get member data: {member_response.text}")
            return None
        
        return {
            'id': user_data['id'],
            'username': user_data['username'],
            'discriminator': user_data.get('discriminator', '0'),
            'avatar': user_data.get('avatar'),
            'roles': user_roles
        }

    def get_user_tier(self, user_roles):
        """Determine user's highest tier based on roles with clear hierarchy"""
        if not user_roles:
            print("DEBUG: No roles found for user")
            return "none"
            
        user_role_ids = set(str(role_id) for role_id in user_roles)
        print(f"DEBUG: User role IDs: {user_role_ids}")
        print(f"DEBUG: Available role IDs: {self.role_ids}")
        
        # Check for tier roles in hierarchy order (highest to lowest)
        if any(role_id in user_role_ids for role_id in self.role_ids["pro"]):
            print("DEBUG: User has PRO tier")
            return "pro"
        elif any(role_id in user_role_ids for role_id in self.role_ids["premium"]):
            print("DEBUG: User has PREMIUM tier")
            return "premium"
        elif any(role_id in user_role_ids for role_id in self.role_ids["boost"]):
            print("DEBUG: User has BOOST tier")
            return "boost"
        elif any(role_id in user_role_ids for role_id in self.role_ids["free"]):
            print("DEBUG: User has FREE tier")
            return "free"
        else:
            print("DEBUG: User has NO tier access")
            return "none"

    def has_no_cooldown(self, user_roles):
        """Check if user has no cooldown perk"""
        if not user_roles:
            return False
            
        user_role_ids = set(str(role_id) for role_id in user_roles)
        has_perk = any(role_id in user_role_ids for role_id in self.role_ids["no_cooldown"])
        print(f"DEBUG: No cooldown perk: {has_perk}")
        return has_perk

    def is_admin(self, user_roles):
        """Check if user is admin"""
        if not user_roles:
            return False
            
        user_role_ids = set(str(role_id) for role_id in user_roles)
        is_admin_user = any(role_id in user_role_ids for role_id in self.role_ids["admin"])
        print(f"DEBUG: Is admin: {is_admin_user}")
        return is_admin_user

    def is_server_member(self, user_roles):
        """Check if user is server member"""
        if not user_roles:
            return False
            
        user_role_ids = set(str(role_id) for role_id in user_roles)
        return any(role_id in user_role_ids for role_id in self.role_ids["member"])

discord_auth = DiscordAuth()

def discord_login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'discord_user' not in session:
            return redirect(url_for('discord_login'))
        return f(*args, **kwargs)
    return decorated_function

# ------------- Helpers -----------------
def load_json(path):
    if not os.path.exists(path): return []
    with open(path, "r", encoding="utf-8") as f:
        try: return json.load(f)
        except: return []

def save_json(path, data):
    with open(path, "w", encoding="utf-8") as f: json.dump(data, f, indent=2)

def load_codes():
    codes = load_json(CODES_FILE)
    # Convert legacy string format to object format
    updated = False
    for i, code in enumerate(codes):
        if isinstance(code, str):
            codes[i] = {"code": code, "used": False, "claimed_by": None, "claimed_at": None, "claimed_ip": None, "discord_id": None}
            updated = True
    if updated:
        save_codes(codes)
    return codes

def save_codes(codes): save_json(CODES_FILE, codes)
def load_premium_codes(): return load_json(PREMIUM_CODES_FILE)
def save_premium_codes(codes): save_json(PREMIUM_CODES_FILE, codes)
def load_ultra_codes(): return load_json(ULTRA_CODES_FILE)
def save_ultra_codes(codes): save_json(ULTRA_CODES_FILE, codes)
def load_zeroad_codes(): return load_json(ZEROAD_CODES_FILE)
def save_zeroad_codes(codes): save_json(ZEROAD_CODES_FILE, codes)

def format_expiry(exp):
    if exp == "never": return "Never"
    return exp[:19].replace("T", " ")

def parse_duration(short, custom_date=None):
    now = datetime.now(timezone.utc)
    mapping = {
        "1d": timedelta(days=1), "3d": timedelta(days=3), "1w": timedelta(weeks=1),
        "2w": timedelta(weeks=2), "1m": timedelta(days=30), "3m": timedelta(days=90),
        "6m": timedelta(days=180), "1y": timedelta(days=365), "100y": timedelta(days=365*100),
    }
    if short == "forever": return "never"
    if short == "custom" and custom_date:
        dt = datetime.strptime(custom_date, "%Y-%m-%d")
        return datetime(dt.year, dt.month, dt.day, 23, 59, 59, tzinfo=timezone.utc).isoformat()
    return (now + mapping.get(short, timedelta(days=1))).isoformat()

def key_status(key):
    if isinstance(key, dict):
        if key.get("used"):
            return "used"
        # For free keys without expiration
        if "expires" not in key:
            return "active"
        # For keys with expiration
        if key.get("expires") == "never":
            return "active"
        try:
            exp = datetime.fromisoformat(key["expires"])
            if exp < datetime.now(timezone.utc):
                return "expired"
        except:
            return "expired"
        return "active"
    else:
        # Handle legacy string format
        return "active"

def generate_code(length=12):
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=length))

def generate_claim_hash(level, session_token):
    # Use a strong hash for the claim link
    raw = f"{level}:{session_token}:{app.secret_key}"
    return hashlib.sha256(raw.encode()).hexdigest()

def generate_progress_hash(level, session_token):
    raw = f"progress:{level}:{session_token}:{app.secret_key}"
    return hashlib.sha256(raw.encode()).hexdigest()

def get_client_ip():
    if request.headers.getlist("X-Forwarded-For"):
        return request.headers.getlist("X-Forwarded-For")[0]
    else:
        return request.remote_addr

# Mobile detection helper
def is_mobile_user():
    user_agent = request.headers.get('User-Agent', '').lower()
    mobile_indicators = ['mobile', 'android', 'iphone', 'ipad', 'windows phone']
    return any(indicator in user_agent for indicator in mobile_indicators)

# ----------------- Main Generator/Tasks Frontend ------------------
LEVEL_LINKS = {
    1: "https://lootdest.org/s?rOIgqc2y",
    2: "https://lootdest.org/s?whIPRzcu",
    3: "https://lootdest.org/s?qED9QSUj"
}
MAX_LEVEL = len(LEVEL_LINKS)

def step_nav(current):
    out = '<div class="steps-nav">'
    for i in range(1, MAX_LEVEL+1):
        out += f'<span class="step-dot{" active" if current==i else ""}{" done" if i<current else ""}{" locked" if i>current else ""}">{i}</span>'
    out += "</div>"
    return out

# Store sponsor links in a JSON file for admin editing
SPONSOR_LINKS_FILE = os.path.join(DATA_DIR, "sponsor_links.json")

def load_sponsor_links():
    # Default links if file doesn't exist
    default = {
        "lootlabs": {
            1: "https://loot-link.com/s?smwwUXU2",
            2: "https://lootdest.org/s?bgX7527q",
            3: "https://loot-link.com/s?udZS38Dy"
        },
        "linkvertise": {
            1: "https://link-hub.net/668573/XueWjE0Ds7AW",
            2: "https://direct-link.net/668573/paPablMXRoXE",
            3: "https://link-target.net/668573/CV26PGyWPFiy"
        }
    }
    if not os.path.exists(SPONSOR_LINKS_FILE):
        save_json(SPONSOR_LINKS_FILE, default)
        return default
    try:
        links = load_json(SPONSOR_LINKS_FILE)
        # Ensure all levels exist
        for k in ["lootlabs", "linkvertise"]:
            if k not in links: links[k] = default[k]
            for i in range(1, MAX_LEVEL+1):
                if str(i) not in links[k]:
                    links[k][str(i)] = default[k][i]
        return links
    except:
        return default

def save_sponsor_links(links):
    save_json(SPONSOR_LINKS_FILE, links)

def is_valid_referrer(referrer, level):
    """Improved referrer validation with better domain matching"""
    if not referrer:
        print(f"DEBUG: No referrer for level {level}")
        return False
    
    sponsors = load_sponsor_links()
    
    # Check both sponsor types
    for sponsor_type in ["lootlabs", "linkvertise"]:
        sponsor_url = sponsors[sponsor_type].get(str(level), "")
        if not sponsor_url:
            continue
            
        # Extract domain from sponsor URL
        try:
            sponsor_domain = urlparse(sponsor_url).netloc
            # Remove www. if present and convert to lowercase
            sponsor_domain = sponsor_domain.replace('www.', '').lower()
            
            # Check if referrer contains sponsor domain
            if sponsor_domain in referrer.lower():
                print(f"DEBUG: Valid referrer match - Level {level}, Sponsor: {sponsor_type}")
                print(f"DEBUG: Referrer: {referrer}")
                print(f"DEBUG: Expected domain: {sponsor_domain}")
                return True
                
        except Exception as e:
            print(f"DEBUG: Error parsing sponsor URL: {e}")
    
    print(f"DEBUG: Invalid referrer for level {level}")
    print(f"DEBUG: Referrer was: {referrer}")
    print(f"DEBUG: Expected domains from sponsor links")
    return False

def ip():
    return request.headers.get("X-Forwarded-For", request.remote_addr)

# Updated to track by Discord ID instead of IP
def can_claim_code():
    if 'discord_user' not in session:
        return False
    
    discord_id = session['discord_user']['id']
    codes_db = load_codes()
    
    # Check if user already has an active key
    for code in codes_db:
        if code.get("discord_id") == discord_id and not code.get("used"):
            return False
    
    return True

def remember_claimed_code():
    # This is now handled by storing discord_id in the code object
    pass

# Clear user keys by Discord ID
def clear_user_keys():
    if 'discord_user' not in session:
        return False
        
    discord_id = session['discord_user']['id']
    codes_db = load_codes()
    updated_codes = []
    cleared_count = 0
    
    for code_obj in codes_db:
        # Remove unused keys for this Discord user
        if code_obj.get("discord_id") == discord_id and not code_obj.get("used"):
            cleared_count += 1
        else:
            updated_codes.append(code_obj)
    
    if cleared_count > 0:
        save_codes(updated_codes)
        return True
    return False

# Get keys for current Discord user
def get_user_keys():
    if 'discord_user' not in session:
        return []
        
    discord_id = session['discord_user']['id']
    codes_db = load_codes()
    user_keys = [code for code in codes_db if code.get("discord_id") == discord_id]
    
    # Format dates for display
    for key in user_keys:
        if key.get("claimed_at"):
            try:
                # Convert ISO format to readable format
                dt = datetime.fromisoformat(key["claimed_at"].replace('Z', '+00:00'))
                key["claimed_at"] = dt.strftime("%Y-%m-%d %H:%M:%S")
            except:
                pass
    return user_keys

# ------------- Generator Helpers -----------------
def get_available_services(user_tier):
    """Get available services based on user tier with stock checking"""
    # First get services user's tier should have access to
    available = TIER_SERVICES.get(user_tier, [])
    
    # Then check stock availability
    services_with_stock = []
    for service in available:
        if service in SERVICE_FILES and user_tier in SERVICE_FILES[service]:
            filename = SERVICE_FILES[service][user_tier]
            if os.path.exists(filename):
                try:
                    with open(filename, 'r', encoding='utf-8') as f:
                        accounts = [line.strip() for line in f if line.strip()]
                    if accounts:
                        services_with_stock.append(service)
                    else:
                        print(f"DEBUG: No stock for {service} ({user_tier})")
                except Exception as e:
                    print(f"DEBUG: Error reading {filename}: {e}")
            else:
                print(f"DEBUG: Stock file missing: {filename}")
        else:
            print(f"DEBUG: Service {service} not configured for tier {user_tier}")
    
    print(f"DEBUG: Final available services for {user_tier}: {services_with_stock}")
    return services_with_stock

def generate_account_from_stock(tier, service):
    """Generate account from stock files"""
    if service not in SERVICE_FILES or tier not in SERVICE_FILES[service]:
        return None
    
    filename = SERVICE_FILES[service][tier]
    
    # Create stock directory if it doesn't exist
    os.makedirs(os.path.dirname(filename), exist_ok=True)
    
    try:
        # Check if file exists, create if it doesn't
        if not os.path.exists(filename):
            print(f"DEBUG: Stock file {filename} doesn't exist, creating empty file")
            with open(filename, 'w', encoding='utf-8') as f:
                f.write('')
            return None
        
        with open(filename, 'r', encoding='utf-8') as f:
            accounts = [line.strip() for line in f if line.strip()]
        
        if not accounts:
            print(f"DEBUG: No accounts in {filename}")
            return None
        
        account = random.choice(accounts)
        
        # Remove the account from stock
        accounts.remove(account)
        with open(filename, 'w', encoding='utf-8') as f:
            f.write('\n'.join(accounts))
        
        return account
    except Exception as e:
        print(f"Error generating account: {e}")
        return None

def check_cooldown(user_id, tier, service):
    """Check if user has cooldown for a service"""
    if 'cooldowns' not in session:
        return False
    
    cooldown_key = f"{user_id}_{tier}_{service}"
    if cooldown_key in session['cooldowns']:
        remaining = session['cooldowns'][cooldown_key] - time.time()
        return remaining > 0
    return False

def set_cooldown(user_id, tier, service):
    """Set cooldown for user"""
    if 'cooldowns' not in session:
        session['cooldowns'] = {}
    
    cooldown_key = f"{user_id}_{tier}_{service}"
    session['cooldowns'][cooldown_key] = time.time() + COOLDOWN_TIMES.get(tier, 300)
    
    # Save session
    session.modified = True

# Create stock directories and files on startup
def initialize_stock_files():
    """Create stock directories and default files if they don't exist"""
    for service, tiers in SERVICE_FILES.items():
        for tier, filename in tiers.items():
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(filename), exist_ok=True)
            
            # Create file if it doesn't exist
            if not os.path.exists(filename):
                print(f"Creating stock file: {filename}")
                with open(filename, 'w', encoding='utf-8') as f:
                    # Add some sample accounts for testing
                    if "roblox" in service.lower():
                        f.write("username:password\n")
                    elif "minecraft" in service.lower():
                        f.write("email:password\n")
                    elif "discord" in service.lower():
                        f.write("email:password:token\n")
                    elif "outlook" in service.lower():
                        f.write("email:password\n")

# ------------- Routes -------------

@app.route("/")
def index():
    session['level'] = 1
    session.pop('user_code', None)
    session.pop('task_started', None)
    return render_template('index.html', is_mobile=is_mobile_user())

@app.route("/help")
def help_page():
    return render_template('help.html', is_mobile=is_mobile_user())

# Discord OAuth Routes
@app.route("/discord/login")
def discord_login():
    if not DISCORD_CLIENT_ID:
        return "Discord OAuth not configured. Please set DISCORD_CLIENT_ID in environment variables."
    return redirect(discord_auth.get_auth_url())

@app.route("/discord/callback")
def discord_callback():
    code = request.args.get('code')
    if not code:
        return redirect(url_for('index'))
    
    access_token = discord_auth.get_access_token(code)
    if not access_token:
        return redirect(url_for('index'))
    
    user_data = discord_auth.get_user_data(access_token)
    if not user_data:
        return redirect(url_for('index'))
    
    # Store user data in session
    session['discord_user'] = user_data
    session['discord_access_token'] = access_token
    
    # Enhanced role checking with debugging
    user_tier = discord_auth.get_user_tier(user_data['roles'])
    has_no_cooldown = discord_auth.has_no_cooldown(user_data['roles'])
    is_admin = discord_auth.is_admin(user_data['roles'])
    is_member = discord_auth.is_server_member(user_data['roles'])
    
    session['user_tier'] = user_tier
    session['has_no_cooldown'] = has_no_cooldown
    session['is_admin'] = is_admin
    session['is_member'] = is_member
    
    # Debug info in session for troubleshooting
    session['debug_roles'] = user_data['roles']
    session['debug_tier_calc'] = {
        'tier': user_tier,
        'no_cooldown': has_no_cooldown,
        'admin': is_admin,
        'member': is_member
    }
    
    print(f"DEBUG: User {user_data['username']} logged in with:")
    print(f"  - Tier: {user_tier}")
    print(f"  - No Cooldown: {has_no_cooldown}")
    print(f"  - Admin: {is_admin}")
    print(f"  - Member: {is_member}")
    print(f"  - Roles: {user_data['roles']}")
    
    return redirect(url_for('generators'))

@app.route("/discord/logout")
def discord_logout():
    session.pop('discord_user', None)
    session.pop('discord_access_token', None)
    session.pop('user_tier', None)
    session.pop('has_no_cooldown', None)
    session.pop('is_admin', None)
    session.pop('is_member', None)
    session.pop('cooldowns', None)
    session.pop('debug_roles', None)
    session.pop('debug_tier_calc', None)
    return redirect(url_for('index'))

# Generators Route with Discord Auth
@app.route("/generators")
@discord_login_required
def generators():
    user_tier = session.get('user_tier', 'none')
    has_no_cooldown = session.get('has_no_cooldown', False)
    discord_user = session.get('discord_user', {})
    
    # Available services based on tier
    available_services = get_available_services(user_tier)
    
    return render_template('generators.html', 
                         user_tier=user_tier,
                         has_no_cooldown=has_no_cooldown,
                         discord_user=discord_user,
                         available_services=available_services,
                         is_mobile=is_mobile_user())

# Generate Account Route
@app.route("/generate/<service>")
@discord_login_required
def generate_account(service):
    user_tier = session.get('user_tier', 'none')
    has_no_cooldown = session.get('has_no_cooldown', False)
    discord_user = session.get('discord_user', {})
    
    # Check if user can access this service
    available_services = get_available_services(user_tier)
    if service not in available_services:
        return jsonify({"success": False, "error": "You don't have access to this service"})
    
    # Check cooldown
    if not has_no_cooldown:
        if check_cooldown(discord_user['id'], user_tier, service):
            cooldown_key = f"{discord_user['id']}_{user_tier}_{service}"
            remaining = session['cooldowns'][cooldown_key] - time.time()
            mins = int(remaining // 60)
            secs = int(remaining % 60)
            return jsonify({
                "success": False, 
                "error": f"Cooldown active. Please wait {mins}m {secs}s"
            })
    
    # Generate account
    account = generate_account_from_stock(user_tier, service)
    if not account:
        return jsonify({"success": False, "error": "Out of stock for this service"})
    
    # Set cooldown (if not no_cooldown)
    if not has_no_cooldown:
        set_cooldown(discord_user['id'], user_tier, service)
    
    return jsonify({
        "success": True,
        "account": account,
        "service": service,
        "tier": user_tier
    })

@app.route("/progress", methods=["GET", "POST"])
@discord_login_required
def progress():
    level = session.get('level', 1)
    if level > MAX_LEVEL: 
        return redirect(url_for('code_page'))
    
    nav = step_nav(level)
    
    if "session_token" not in session:
        session["session_token"] = secrets.token_hex(16)
    
    session_token = session["session_token"]
    sponsor_links = load_sponsor_links()
    
    lootlabs_url = sponsor_links["lootlabs"].get(str(level), "")
    linkvertise_url = sponsor_links["linkvertise"].get(str(level), "")
    
    task_started = session.get('task_started')
    claim_enabled = (task_started == level)
    
    # Generate claim button HTML
    claim_btn_html = ""
    if claim_enabled:
        claim_link = url_for(f'claim{level}')
        claim_btn_html = f"""
        <form action="{claim_link}" method="get" style="margin-top:1.2em;">
            <button class="progress-btn claim-btn" type="submit">Claim Step {level}</button>
        </form>
        """
    
    # Generate sponsor buttons
    sponsor_buttons = ""
    if lootlabs_url:
        sponsor_buttons += f'<a href="{url_for("start_task", lv=level, token=session_token, sponsor="lootlabs")}" target="_blank"><button class="progress-btn sponsor-btn">Complete LootLabs Task</button></a>'
    if linkvertise_url:
        sponsor_buttons += f'<a href="{url_for("start_task", lv=level, token=session_token, sponsor="linkvertise")}" target="_blank" style="margin-left:0.7em;"><button class="progress-btn sponsor-btn">Complete Linkvertise Task</button></a>'
    
    # Add debug info for troubleshooting
    debug_info = {
        'current_level': level,
        'task_started': task_started,
        'claim_enabled': claim_enabled,
        'max_level': MAX_LEVEL
    }
    
    return render_template('progress.html', 
                         nav=nav, 
                         level=level, 
                         max_level=MAX_LEVEL,
                         sponsor_buttons=Markup(sponsor_buttons),
                         claim_btn_html=Markup(claim_btn_html),
                         debug_info=debug_info,
                         is_mobile=is_mobile_user())

@app.route("/start_task")
@discord_login_required
def start_task():
    try: 
        level = int(request.args.get('lv', 1))
    except: 
        level = 1
    
    sponsor = request.args.get('sponsor', 'lootlabs')
    
    # Set task started for this level
    session['task_started'] = level
    session['task_started_time'] = time.time()
    
    sponsor_links = load_sponsor_links()
    
    if sponsor == "linkvertise":
        sponsor_url = sponsor_links["linkvertise"].get(str(level), "")
    else:
        sponsor_url = sponsor_links["lootlabs"].get(str(level), "")
    
    print(f"DEBUG START_TASK: Level {level}, Sponsor: {sponsor}, URL: {sponsor_url}")
    
    if not sponsor_url:
        return render_template('claim_error.html',
                             message="Sponsor link not configured for this level.",
                             return_url=url_for('progress'),
                             is_mobile=is_mobile_user())
    
    return redirect(sponsor_url)

@app.route("/claim1")
@discord_login_required
def claim1():
    ref = request.headers.get('Referer', '')
    print(f"DEBUG CLAIM1: Referrer = {ref}")
    
    if not is_valid_referrer(ref, 1):
        session['level'] = 1
        session.pop('task_started', None)
        session.pop('task_started_time', None)
        return render_template('claim_error.html', 
                             message="Invalid referrer. Please complete the sponsor task properly.",
                             return_url=url_for('progress'),
                             is_mobile=is_mobile_user())
    
    cur = session.get('level', 1)
    task_started = session.get('task_started')
    
    print(f"DEBUG CLAIM1: Current level = {cur}, Task started = {task_started}")
    
    if cur != 1 or task_started != 1:
        return render_template('claim_error.html', 
                             message="You must click <b>Start Task</b> for this sponsor before claiming.",
                             return_url=url_for('progress'),
                             is_mobile=is_mobile_user())
    
    # Success - move to next level
    session['level'] = 2
    session.pop('task_started', None)
    session.pop('task_started_time', None)
    
    print(f"DEBUG CLAIM1: Success! Moving to level 2")
    return redirect(url_for('progress'))

@app.route("/claim2")
@discord_login_required
def claim2():
    ref = request.headers.get('Referer', '')
    print(f"DEBUG CLAIM2: Referrer = {ref}")
    
    if not is_valid_referrer(ref, 2):
        session['level'] = 2  # Don't reset to 1, stay at current level
        session.pop('task_started', None)
        session.pop('task_started_time', None)
        return render_template('claim_error.html', 
                             message="Invalid referrer. Please complete the sponsor task properly.",
                             return_url=url_for('progress'),
                             is_mobile=is_mobile_user())
    
    cur = session.get('level', 1)
    task_started = session.get('task_started')
    
    print(f"DEBUG CLAIM2: Current level = {cur}, Task started = {task_started}")
    
    if cur != 2 or task_started != 2:
        return render_template('claim_error.html', 
                             message="You must click <b>Start Task</b> for this sponsor before claiming.",
                             return_url=url_for('progress'),
                             is_mobile=is_mobile_user())
    
    session['level'] = 3
    session.pop('task_started', None)
    session.pop('task_started_time', None)
    
    print(f"DEBUG CLAIM2: Success! Moving to level 3")
    return redirect(url_for('progress'))

@app.route("/claim3")
@discord_login_required
def claim3():
    ref = request.headers.get('Referer', '')
    print(f"DEBUG CLAIM3: Referrer = {ref}")
    
    if not is_valid_referrer(ref, 3):
        session['level'] = 3  # Don't reset to 1, stay at current level
        session.pop('task_started', None)
        session.pop('task_started_time', None)
        return render_template('claim_error.html', 
                             message="Invalid referrer. Please complete the sponsor task properly.",
                             return_url=url_for('progress'),
                             is_mobile=is_mobile_user())
    
    cur = session.get('level', 1)
    task_started = session.get('task_started')
    
    print(f"DEBUG CLAIM3: Current level = {cur}, Task started = {task_started}")
    
    if cur != 3 or task_started != 3:
        return render_template('claim_error.html', 
                             message="You must click <b>Start Task</b> for this sponsor before claiming.",
                             return_url=url_for('progress'),
                             is_mobile=is_mobile_user())
    
    session['level'] = 4  # Move to code page
    session.pop('task_started', None)
    session.pop('task_started_time', None)
    
    print(f"DEBUG CLAIM3: Success! Moving to code page")
    return redirect(url_for('code_page'))

@app.route("/code")
@discord_login_required
def code_page():
    if session.get('level', 1) <= MAX_LEVEL: 
        return redirect(url_for('progress'))
    
    code = session.get('user_code')
    if not code:
        if not can_claim_code():
            return render_template('code_page.html', error=True, is_mobile=is_mobile_user())
        codes_db = load_codes()
        code_value = generate_code()
        discord_user = session.get('discord_user', {})
        code_obj = {
            "code": code_value,
            "used": False,
            "claimed_by": None,
            "claimed_at": None,
            "claimed_ip": get_client_ip(),
            "discord_id": discord_user.get('id'),
            "discord_username": f"{discord_user.get('username')}#{discord_user.get('discriminator', '0')}"
        }
        codes_db.append(code_obj)
        save_codes(codes_db)
        session['user_code'] = code_value
        code = code_value
    
    nav = step_nav(MAX_LEVEL+1)
    return render_template('code_page.html', nav=Markup(nav), code=code, is_mobile=is_mobile_user())

@app.route("/key_options")
def key_options():
    return render_template('key_options.html', is_mobile=is_mobile_user())

# New route for key management page
@app.route("/key_management")
@discord_login_required
def key_management():
    discord_user = session.get('discord_user', {})
    current_user = f"{discord_user.get('username')}#{discord_user.get('discriminator', '0')}"
    return render_template('key_management.html', current_user=current_user, is_mobile=is_mobile_user())

# New route to show keys for current Discord user
@app.route("/show_keys")
@discord_login_required
def show_keys():
    discord_user = session.get('discord_user', {})
    current_user = f"{discord_user.get('username')}#{discord_user.get('discriminator', '0')}"
    user_keys = get_user_keys()
    return render_template('show_keys.html', keys=user_keys, current_user=current_user, is_mobile=is_mobile_user())

# Route to clear user keys
@app.route("/clear_keys")
@discord_login_required
def clear_keys():
    success = clear_user_keys()
    if success:
        return render_template('clear_success.html', is_mobile=is_mobile_user())
    else:
        return render_template('clear_error.html', is_mobile=is_mobile_user())

@app.route("/store")
def store():
    return render_template('store.html', is_mobile=is_mobile_user())

# ------------- Admin Routes -------------

@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    # If already logged in, redirect to admin dashboard
    if session.get(ADMIN_SESSION_KEY):
        return redirect(url_for('admin'))
    
    error = None
    if request.method == "POST":
        password = request.form.get("password", "").strip()
        if password == ADMIN_PASSWORD:
            session[ADMIN_SESSION_KEY] = True
            return redirect(url_for('admin'))
        else:
            error = "Invalid password. Please try again."
    
    return render_template('admin_login.html', error=error)

@app.route("/admin", methods=["GET", "POST"])
def admin():
    # Check if user is already logged in
    if not session.get(ADMIN_SESSION_KEY):
        return redirect(url_for('admin_login'))
    
    # Handle login via main admin route (for backward compatibility)
    if request.method == "POST" and not session.get(ADMIN_SESSION_KEY):
        pw = request.form.get("password", "")
        if pw == ADMIN_PASSWORD:
            session[ADMIN_SESSION_KEY] = True
        else:
            return render_template('admin_login.html', error="Invalid password")
    
    # If still not logged in after POST, redirect to login
    if not session.get(ADMIN_SESSION_KEY):
        return redirect(url_for('admin_login'))
    
    premium = load_premium_codes()
    ultra = load_ultra_codes()
    zeroad = load_zeroad_codes()
    
    # --- Mass Free Key Generation ---
    mass_free_msg = ""
    if request.method == "POST" and "mass_free_count" in request.form:
        try:
            count = int(request.form.get("mass_free_count", "0"))
            prefix = request.form.get("mass_free_prefix", "HULK")
            if 1 <= count <= 1000:
                codes = load_codes()
                new_codes = [{
                    "code": f"{prefix}-{generate_code(10)}",
                    "used": False,
                    "claimed_by": None,
                    "claimed_at": None,
                    "claimed_ip": None,
                    "discord_id": None,
                    "discord_username": None
                } for _ in range(count)]
                codes.extend(new_codes)
                save_codes(codes)
                mass_free_msg = f"Generated {count} free keys with prefix '{prefix}'."
            else:
                mass_free_msg = "Enter a number between 1 and 1000."
        except Exception:
            mass_free_msg = "Invalid input for mass free key generation."
    
    def status(key): return key_status(key)
    keys = (
        [ { "type": "premium", "code": k["code"], "expires": format_expiry(k["expires"]), "status": status(k) } for k in premium ] +
        [ { "type": "ultra", "code": k["code"], "expires": format_expiry(k["expires"]), "status": status(k) } for k in ultra ] +
        [ { "type": "zeroad", "code": k["code"], "expires": format_expiry(k["expires"]), "status": status(k) } for k in zeroad ]
    )
    keys = sorted(keys, key=lambda x: (x['type'], x['status'], x['expires']))
    
    return render_template('admin_dashboard.html', 
                         keys=keys, 
                         mass_free_msg=mass_free_msg)

# Admin API to directly access code page
@app.route("/admin/api/code_page", methods=["GET", "POST"])
def admin_api_code_page():
    if not session.get(ADMIN_SESSION_KEY):
        return jsonify({"success": False, "error": "Admin authentication required"}), 401
    
    # Generate a code directly for admin
    codes_db = load_codes()
    code_value = generate_code()
    code_obj = {
        "code": code_value,
        "used": False,
        "claimed_by": "admin",
        "claimed_at": datetime.now(timezone.utc).isoformat(),
        "claimed_ip": get_client_ip(),
        "discord_id": "admin",
        "discord_username": "admin"
    }
    codes_db.append(code_obj)
    save_codes(codes_db)
    
    # Set session to completed state
    session['user_code'] = code_value
    session['level'] = MAX_LEVEL + 1
    
    # If it's an API request (JSON), return the code
    if request.headers.get('Content-Type') == 'application/json' or request.args.get('format') == 'json':
        return jsonify({
            "success": True,
            "code": code_value,
            "message": "Admin code generated successfully",
            "redirect_url": url_for('code_page')
        })
    
    # Otherwise redirect to the code page
    return redirect(url_for('code_page'))

@app.route("/admin/add", methods=["POST"])
def admin_add_key():
    if not session.get(ADMIN_SESSION_KEY): 
        return redirect(url_for('admin_login'))
    
    keytype = request.form.get("keytype")
    duration = request.form.get("duration")
    custom_date = request.form.get("custom_date")
    if keytype not in ("premium", "ultra", "zeroad"): 
        return redirect(url_for('admin'))
    
    code = generate_code(12)
    expires = parse_duration(duration, custom_date)
    keydata = {
        "code": code,
        "expires": expires,
        "used": False,
        "claimed_by": None,
        "claimed_at": None,
        "claimed_ip": None
    }
    if keytype == "premium":
        codes = load_premium_codes()
        codes.append(keydata)
        save_premium_codes(codes)
    elif keytype == "ultra":
        codes = load_ultra_codes()
        codes.append(keydata)
        save_ultra_codes(codes)
    elif keytype == "zeroad":
        codes = load_zeroad_codes()
        codes.append(keydata)
        save_zeroad_codes(codes)
    return redirect(url_for('admin'))

@app.route("/admin/freecodes", methods=["GET", "POST"])
def admin_freecodes():
    if not session.get(ADMIN_SESSION_KEY):
        return redirect(url_for('admin_login'))

    codes = load_codes()
    msg = ""
    search_term = request.form.get("search_term", "").strip().upper()
    search_filter = request.form.get("search_filter", "all")
    filtered_codes = codes

    # Apply search filter if provided
    if search_term:
        if search_filter == "key":
            filtered_codes = [code for code in codes if search_term in code.get("code", "").upper()]
        elif search_filter == "user":
            filtered_codes = [code for code in codes if code.get("claimed_by") and search_term in code.get("claimed_by", "").upper()]
        elif search_filter == "date":
            filtered_codes = [code for code in codes if code.get("claimed_at") and search_term in code.get("claimed_at", "")]
        elif search_filter == "ip":
            filtered_codes = [code for code in codes if code.get("claimed_ip") and search_term in code.get("claimed_ip", "")]
        elif search_filter == "discord":
            filtered_codes = [code for code in codes if code.get("discord_id") and search_term in code.get("discord_id", "")]
        else:  # "all"
            filtered_codes = [
                code for code in codes
                if (search_term in code.get("code", "").upper() or
                    (code.get("claimed_by") and search_term in code.get("claimed_by", "").upper()) or
                    (code.get("claimed_at") and search_term in code.get("claimed_at", "")) or
                    (code.get("claimed_ip") and search_term in code.get("claimed_ip", "")) or
                    (code.get("discord_id") and search_term in code.get("discord_id", "")) or
                    (code.get("discord_username") and search_term in code.get("discord_username", "").upper()))
            ]

    # Handle button actions
    if request.method == "POST":
        action = request.form.get("action")
        if action == "add_hulk":
            new_code = {
                "code": "HULK-" + generate_code(10),
                "used": False,
                "claimed_by": None,
                "claimed_at": None,
                "claimed_ip": None,
                "discord_id": None,
                "discord_username": None
            }
            codes.append(new_code)
            save_codes(codes)
            msg = "Hulk code added."
            filtered_codes = codes  # Refresh filtered list

        elif action == "add_one":
            new_code = {
                "code": "ONE-" + generate_code(10),
                "used": False,
                "claimed_by": None,
                "claimed_at": None,
                "claimed_ip": None,
                "discord_id": None,
                "discord_username": None
            }
            codes.append(new_code)
            save_codes(codes)
            msg = "One code added."
            filtered_codes = codes  # Refresh filtered list

        elif action == "add_custom":
            custom_code = request.form.get("custom_code", "").strip().upper()
            if custom_code:
                new_code = {
                    "code": custom_code,
                    "used": False,
                    "claimed_by": None,
                    "claimed_at": None,
                    "claimed_ip": None,
                    "discord_id": None,
                    "discord_username": None
                }
                codes.append(new_code)
                save_codes(codes)
                msg = f"Custom code '{custom_code}' added."
                filtered_codes = codes  # Refresh filtered list
            else:
                msg = "Please enter a valid code."

        elif action == "delete_selected":
            selected_codes = request.form.getlist("selected_codes")
            if selected_codes:
                codes = [code for code in codes if code.get("code") not in selected_codes]
                save_codes(codes)
                msg = f"Deleted {len(selected_codes)} codes."
                filtered_codes = codes  # Refresh filtered list
            else:
                msg = "No codes selected for deletion."

        elif action == "search":
            # Search is handled above by the search_term variable
            pass

    return render_template('admin_freecodes.html',
                         codes=codes,
                         filtered_codes=filtered_codes,
                         search_term=search_term,
                         search_filter=search_filter,
                         message=msg)

@app.route("/admin/export_free_keys")
def admin_export_free_keys():
    if not session.get(ADMIN_SESSION_KEY):
        return redirect(url_for('admin_login'))

    status_filter = request.args.get('status', 'all')
    codes = load_codes()

    if status_filter == 'active':
        codes = [code for code in codes if not code.get('used')]
    elif status_filter == 'used':
        codes = [code for code in codes if code.get('used')]

    # Create CSV in memory
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Key', 'Status', 'Claimed By', 'Claimed At', 'IP Address', 'Discord ID', 'Discord Username'])

    for code in codes:
        writer.writerow([
            code['code'],
            'Used' if code.get('used') else 'Active',
            code.get('claimed_by', ''),
            code.get('claimed_at', ''),
            code.get('claimed_ip', ''),
            code.get('discord_id', ''),
            code.get('discord_username', '')
        ])

    output.seek(0)
    filename = f"free_keys_{status_filter}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"

    return send_file(
        io.BytesIO(output.getvalue().encode()),
        mimetype='text/csv',
        as_attachment=True,
        download_name=filename
    )

@app.route("/admin/remove", methods=["GET", "POST"])
def admin_remove_keys():
    if not session.get(ADMIN_SESSION_KEY):
        return redirect(url_for('admin_login'))
    
    premium = load_premium_codes()
    ultra = load_ultra_codes()
    zeroad = load_zeroad_codes()
    
    message = ""
    if request.method == "POST":
        code = request.form.get("removecode","").strip().upper()
        found = False
        for db, loader, saver in [
            (premium, load_premium_codes, save_premium_codes),
            (ultra, load_ultra_codes, save_ultra_codes),
            (zeroad, load_zeroad_codes, save_zeroad_codes)
        ]:
            orig = len(db)
            db = [k for k in db if k["code"].upper() != code]
            if len(db) != orig:
                saver(db)
                found = True
        freecodes = load_codes()
        orig = len(freecodes)
        freecodes = [c for c in freecodes if c.get("code", "").upper() != code]
        if len(freecodes) != orig:
            save_codes(freecodes)
            found = True
        message = f"Key {code} {'removed' if found else 'not found'}."
    
    recent_keys = [k['code'] for k in (premium+ultra+zeroad)[-8:]]
    return render_template('admin_remove_keys.html',
                         message=message,
                         recent_keys=recent_keys)

@app.route("/admin/download/<keytype>")
def admin_download(keytype):
    if not session.get(ADMIN_SESSION_KEY): 
        return redirect(url_for('admin_login'))
    
    if keytype == "premium": 
        codes = load_premium_codes()
    elif keytype == "ultra": 
        codes = load_ultra_codes()
    elif keytype == "zeroad": 
        codes = load_zeroad_codes()
    else: 
        return redirect(url_for('admin'))
    
    content = "\n".join([k["code"] for k in codes if not k.get("used", False)])
    return (content, 200, {
        'Content-Type': 'text/plain; charset=utf-8',
        'Content-Disposition': f'attachment; filename="{keytype}_keys.txt"'
    })

@app.route("/admin/sponsors", methods=["GET", "POST"])
def admin_sponsors():
    if not session.get(ADMIN_SESSION_KEY):
        return redirect(url_for('admin_login'))
    
    sponsor_links = load_sponsor_links()
    msg = ""
    if request.method == "POST":
        for k in ["lootlabs", "linkvertise"]:
            for i in range(1, MAX_LEVEL+1):
                field = f"{k}_{i}"
                url = request.form.get(field, "").strip()
                if url:
                    sponsor_links[k][str(i)] = url
        save_sponsor_links(sponsor_links)
        msg = "Sponsor links updated."
    
    return render_template('admin_sponsors.html', 
                         sponsor_links=sponsor_links, 
                         max_level=MAX_LEVEL, 
                         message=msg)

@app.route("/admin/logout", methods=["POST"])
def admin_logout():
    session.pop(ADMIN_SESSION_KEY, None)
    return redirect(url_for('index'))

# Debug route for session inspection
@app.route("/debug/session")
@discord_login_required
def debug_session():
    """Debug route to check session state"""
    session_data = {
        'level': session.get('level'),
        'task_started': session.get('task_started'),
        'task_started_time': session.get('task_started_time'),
        'user_code': session.get('user_code'),
        'discord_user': session.get('discord_user', {}).get('username'),
        'user_tier': session.get('user_tier'),
        'session_token': session.get('session_token')
    }
    return jsonify(session_data)

if __name__ == "__main__":
    app.wsgi_app = ProxyFix(app.wsgi_app)
    
    # Create stock directories
    for folder in STOCK_FOLDERS.values():
        os.makedirs(folder, exist_ok=True)
    
    # Initialize stock files
    initialize_stock_files()
    
    print("="*48)
    print(" Ryu Market Generator Server & Admin Panel ONLINE ")
    print(" Website: http://localhost:8080")
    print(" Admin Panel: http://localhost:8080/admin")
    print(" Admin Login: http://localhost:8080/admin/login")
    print(" Help Page: http://localhost:8080/help")
    print(" Store: http://localhost:8080/store")
    print(" Key Management: http://localhost:8080/key_management")
    print(" Clear Keys: http://localhost:8080/clear_keys")
    print(" Show Keys: http://localhost:8080/show_keys")
    print(" Generators: http://localhost:8080/generators")
    print(" Admin Code API: http://localhost:8080/admin/api/code_page")
    print(" Debug Session: http://localhost:8080/debug/session")
    print("="*48)
    
    app.run(port=8080, debug=True)

# Add this line for PythonAnywhere
application = app