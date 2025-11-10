
# main.py — FINAL PRODUCTION VERSION FOR RENDER
from flask import Flask, request, jsonify, redirect, send_from_directory, make_response
import stripe
import requests
import jwt
import sqlite3
import os
from datetime import datetime, timedelta
from urllib.parse import urlencode

# === FLASK APP ===
app = Flask(__name__, static_folder='.', static_url_path='')
app.secret_key = os.getenv('SECRET_KEY')

# === CONFIG — ALL FROM ENV ===
stripe.api_key = os.getenv('STRIPE_API_KEY')
GROK_API_KEY = os.getenv('GROK_API_KEY')
DOMAIN = os.getenv('DOMAIN')  # e.g., https://your-app.onrender.com

# OAuth Clients (exact env var names)
GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID')
GOOGLE_CLIENT_SECRET = os.getenv('GOOGLE_CLIENT_SECRET')
SHOPIFY_API_KEY = os.getenv('SHOPIFY_API_KEY')          # Client ID
SHOPIFY_CLIENT_SECRET = os.getenv('SHOPIFY_CLIENT_SECRET')
HUBSPOT_CLIENT_ID = os.getenv('HUBSPOT_CLIENT_ID')
HUBSPOT_CLIENT_SECRET = os.getenv('HUBSPOT_CLIENT_SECRET')

# === SQLITE DATABASE ===
DB_FILE = "data.db"

def init_db():
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                stripe_id TEXT,
                shopify_shop TEXT,
                ga4_connected INTEGER DEFAULT 0,
                hubspot_connected INTEGER DEFAULT 0,
                ga4_access_token TEXT,
                ga4_refresh_token TEXT,
                shopify_access_token TEXT,
                hubspot_refresh_token TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                date TEXT DEFAULT CURRENT_TIMESTAMP,
                revenue REAL DEFAULT 0,
                churn_rate REAL DEFAULT 0,
                at_risk INTEGER DEFAULT 0,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        """)
        conn.commit()
init_db()

# === AUTH HELPERS ===
def get_user_id_from_token():
    token = request.cookies.get('token')
    if not token:
        return None
    try:
        payload = jwt.decode(token, app.secret_key, algorithms=["HS256"])
        return int(payload["sub"])
    except:
        return None

def require_auth():
    user_id = get_user_id_from_token()
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401
    return user_id

# === ROUTES ===
@app.route('/')
def index():
    return send_from_directory('.', 'index.html')

@app.route('/<path:path>')
def static_files(path):
    return send_from_directory('.', path)

# === SIGNUP + STRIPE TRIAL ===
@app.route('/create-trial', methods=['POST'])
def create_trial():
    email = request.json.get('email', '').strip().lower()
    if not email or '@' not in email or '.' not in email:
        return jsonify({"error": "Valid email required"}), 400

    try:
        customer = stripe.Customer.create(email=email)
        stripe.Subscription.create(
            customer=customer.id,
            items=[{"price": os.getenv('STRIPE_PRICE_ID')}],
            trial_period_days=7,
            payment_behavior='default_incomplete'
        )
    except stripe.error.StripeError as e:
        return jsonify({"error": str(e)}), 400

    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT OR IGNORE INTO users (email, stripe_id) VALUES (?, ?)",
            (email, customer.id)
        )
        conn.commit()
        user_id = cursor.lastrowid or cursor.execute(
            "SELECT id FROM users WHERE email = ?", (email,)
        ).fetchone()[0]

    token = jwt.encode(
        {"sub": str(user_id), "exp": datetime.utcnow() + timedelta(days=7)},
        app.secret_key, algorithm="HS256"
    )

    resp = make_response(redirect('/index.html'))
    resp.set_cookie(
        'token', token,
        httponly=True, secure=True, samesite='Lax',
        max_age=7*24*60*60
    )
    return resp

# === METRICS ===
@app.route('/api/metrics')
def metrics():
    user_id = require_auth()
    if isinstance(user_id, tuple):
        return user_id

    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT revenue, churn_rate, at_risk FROM metrics WHERE user_id = ? ORDER BY date DESC LIMIT 1",
            (user_id,)
        )
        row = cursor.fetchone()

    if row:
        return jsonify({
            "revenue": {"total": row[0], "trend": "+6%"},
            "churn": {"rate": row[1], "at_risk": row[2]},
            "ai_insight": f"Send win-back email to {row[2]} at-risk → save £2,400/mo."
        })
    else:
        return jsonify({
            "revenue": {"total": 0, "trend": "0%"},
            "churn": {"rate": 0, "at_risk": 0},
            "ai_insight": "Connect Shopify to unlock real insights."
        })

# === AI CHAT (GROK) ===
@app.route('/api/chat', methods=['POST'])
def ai_chat():
    user_id = require_auth()
    if isinstance(user_id, tuple):
        return user_id

    message = request.json.get('message', '').strip()
    if not message:
        return jsonify({"reply": "Ask me about churn, revenue, or growth."})

    try:
        response = requests.post(
            "https://api.x.ai/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {GROK_API_KEY}",
                "Content-Type": "application/json"
            },
            json={
                "model": "grok-beta",
                "messages": [{"role": "user", "content": message}],
                "temperature": 0.7
            },
            timeout=20
        )
        response.raise_for_status()
        reply = response.json()["choices"][0]["message"]["content"]
    except Exception as e:
        print("Grok API error:", e)
        reply = "I'm analyzing your store... try again in 10s."

    return jsonify({"reply": reply})

# === OAUTH: START ===
@app.route('/auth/<provider>')
def oauth_start(provider):
    user_id = get_user_id_from_token()
    if not user_id:
        return redirect(f"/?error=login_required")

    shop = request.args.get('shop', '').strip() if provider == 'shopify' else None

    if provider == 'shopify':
        if not shop or not shop.endswith('.myshopify.com'):
            return "Invalid Shopify store", 400
        params = {
            'client_id': SHOPIFY_API_KEY,
            'scope': 'read_orders,read_customers,read_products',
            'redirect_uri': f"{DOMAIN}/auth/shopify/callback",
            'state': f"{user_id}|{shop}"
        }
        auth_url = f"https://{shop}/admin/oauth/authorize?{urlencode(params)}"
        return redirect(auth_url)

    elif provider == 'ga4':
        params = {
            'client_id': GOOGLE_CLIENT_ID,
            'redirect_uri': f"{DOMAIN}/auth/ga4/callback",
            'response_type': 'code',
            'scope': 'https://www.googleapis.com/auth/analytics.readonly',
            'access_type': 'offline',
            'prompt': 'consent',
            'state': str(user_id)
        }
        auth_url = f"https://accounts.google.com/o/oauth2/v2/auth?{urlencode(params)}"
        return redirect(auth_url)

    elif provider == 'hubspot':
        params = {
            'client_id': HUBSPOT_CLIENT_ID,
            'redirect_uri': f"{DOMAIN}/auth/hubspot/callback",
            'scope': 'contacts crm.objects.contacts.read',
            'response_type': 'code',
            'state': str(user_id)
        }
        auth_url = f"https://app.hubspot.com/oauth/authorize?{urlencode(params)}"
        return redirect(auth_url)

    return "Invalid provider", 400

# === OAUTH: CALLBACKS ===
@app.route('/auth/shopify/callback')
def shopify_callback():
    code = request.args.get('code')
    state = request.args.get('state')
    if not code or not state:
        return "Missing code or state", 400

    try:
        user_id, shop = state.split('|', 1)
        user_id = int(user_id)
    except:
        return "Invalid state", 400

    token_url = f"https://{shop}/admin/oauth/access_token"
    payload = {
        'client_id': SHOPIFY_API_KEY,
        'client_secret': SHOPIFY_CLIENT_SECRET,
        'code': code
    }
    resp = requests.post(token_url, data=payload)
    if resp.status_code != 200:
        return "Shopify auth failed", 400
    token_data = resp.json()
    access_token = token_data['access_token']

    with sqlite3.connect(DB_FILE) as conn:
        conn.execute(
            "UPDATE users SET shopify_shop = ?, shopify_access_token = ? WHERE id = ?",
            (shop, access_token, user_id)
        )
        conn.commit()

    return "<script>localStorage.setItem('shopify','connected');window.close();</script>"

@app.route('/auth/ga4/callback')
def ga4_callback():
    code = request.args.get('code')
    state = request.args.get('state')
    if not code or not state:
        return "Missing code or state", 400

    user_id = int(state)

    token_url = "https://oauth2.googleapis.com/token"
    payload = {
        'code': code,
        'client_id': GOOGLE_CLIENT_ID,
        'client_secret': GOOGLE_CLIENT_SECRET,
        'redirect_uri': f"{DOMAIN}/auth/ga4/callback",
        'grant_type': 'authorization_code'
    }
    resp = requests.post(token_url, data=payload)
    if resp.status_code != 200:
        return f"GA4 auth failed: {resp.text}", 400
    token_data = resp.json()

    access_token = token_data['access_token']
    refresh_token = token_data.get('refresh_token')

    with sqlite3.connect(DB_FILE) as conn:
        conn.execute(
            """UPDATE users SET 
               ga4_connected = 1,
               ga4_access_token = ?,
               ga4_refresh_token = ?
               WHERE id = ?""",
            (access_token, refresh_token, user_id)
        )
        conn.commit()

    return "<script>localStorage.setItem('ga4','connected');window.close();</script>"

@app.route('/auth/hubspot/callback')
def hubspot_callback():
    code = request.args.get('code')
    state = request.args.get('state')
    if not code or not state:
        return "Missing code or state", 400

    user_id = int(state)

    token_url = "https://api.hubapi.com/auth/v1/oauth/v2/token"
    payload = {
        'grant_type': 'authorization_code',
        'client_id': HUBSPOT_CLIENT_ID,
        'client_secret': HUBSPOT_CLIENT_SECRET,
        'redirect_uri': f"{DOMAIN}/auth/hubspot/callback",
        'code': code
    }
    resp = requests.post(token_url, data=payload)
    if resp.status_code != 200:
        return f"HubSpot auth failed: {resp.text}", 400
    token_data = resp.json()

    access_token = token_data['access_token']
    refresh_token = token_data['refresh_token']

    with sqlite3.connect(DB_FILE) as conn:
        conn.execute(
            """UPDATE users SET 
               hubspot_connected = 1,
               hubspot_refresh_token = ?
               WHERE id = ?""",
            (refresh_token, user_id)
        )
        conn.commit()

    return "<script>localStorage.setItem('hubspot','connected');window.close();</script>"

# === DEBUG: View user data (optional) ===
@app.route('/api/user')
def user_debug():
    user_id = get_user_id_from_token()
    if not user_id:
        return jsonify({"error": "Not logged in"}), 401

    with sqlite3.connect(DB_FILE) as conn:
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        row = cur.fetchone()
        if not row:
            return jsonify({"error": "User not found"}), 404
        keys = [desc[0] for desc in cur.description]
        return jsonify(dict(zip(keys, row)))

# === HEALTH CHECK ===
@app.route('/health')
def health():
    return jsonify({"status": "ok", "time": datetime.utcnow().isoformat()})

# === NO if __name__ == '__main__' — RENDER USES GUNICORN ===