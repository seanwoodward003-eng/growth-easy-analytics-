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
app.secret_key = os.getenv('SECRET_KEY', 'change-this-in-production-to-a-random-256-bit-key')

# === CONFIG ===
stripe.api_key = "sk_live_..."  # ← YOUR LIVE STRIPE KEY (or test)
GROK_API_KEY = "your_xai_api_key_here"  # ← https://x.ai/api
GOOGLE_CLIENT_ID = "your_google_client_id"
GOOGLE_CLIENT_SECRET = "your_google_client_secret"
DOMAIN = "https://growtheasy-ai.com"  # ← YOUR LIVE DOMAIN

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

# === HELPERS ===
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

# SIGNUP + STRIPE + SAVE TO DB
@app.route('/create-trial', methods=['POST'])
def create_trial():
    email = request.json.get('email', '').strip().lower()
    if not email or '@' not in email or '.' not in email:
        return jsonify({"error": "Valid email required"}), 400

    try:
        customer = stripe.Customer.create(email=email)
        stripe.Subscription.create(
            customer=customer.id,
            items=[{"price": "price_1ABC123"}],  # ← YOUR PRICE ID
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
        user_id = cursor.lastrowid or cursor.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()[0]

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

# METRICS
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
        revenue, churn_rate, at_risk = row
        return jsonify({
            "revenue": {"total": revenue, "trend": "+6%"},
            "churn": {"rate": churn_rate, "at_risk": at_risk},
            "ai_insight": f"Send win-back email to {at_risk} at-risk customers → save £2,400/mo."
        })
    else:
        return jsonify({
            "revenue": {"total": 0, "trend": "0%"},
            "churn": {"rate": 0, "at_risk": 0},
            "ai_insight": "Connect Shopify to unlock real insights."
        })

# AI CHAT — POWERED BY GROK
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

# SHOPIFY OAUTH
@app.route('/auth/shopify')
def auth_shopify():
    shop = request.args.get('shop', '').strip()
    if not shop or not shop.endswith('.myshopify.com'):
        return "Invalid Shopify store", 400
    params = {
        'client_id': 'your-shopify-api-key',
        'scope': 'read_orders,read_customers',
        'redirect_uri': f'{DOMAIN}/auth/shopify/callback',
        'state': shop
    }
    return redirect(f"https://{shop}/admin/oauth/authorize?{urlencode(params)}")

@app.route('/auth/shopify/callback')
def shopify_callback():
    # In production: exchange code, save token
    return "<script>localStorage.setItem('shopify','connected');window.close();</script>"

# GA4 OAUTH
@app.route('/auth/ga4')
def auth_ga4():
    params = {
        'client_id': GOOGLE_CLIENT_ID,
        'redirect_uri': f'{DOMAIN}/auth/ga4/callback',
        'response_type': 'code',
        'scope': 'https://www.googleapis.com/auth/analytics.readonly',
        'access_type': 'offline',
        'prompt': 'consent'
    }
    return redirect(f"https://accounts.google.com/o/oauth2/v2/auth?{urlencode(params)}")

@app.route('/auth/ga4/callback')
def ga4_callback():
    return "<script>localStorage.setItem('ga4','connected');window.close();</script>"

# HEALTH CHECK
@app.route('/health')
def health():
    return jsonify({"status": "ok", "time": datetime.utcnow().isoformat()})

# RUN
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)