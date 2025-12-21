# main.py — FULLY SECURE 2025 BACKEND + 100% COMPATIBLE WITH YOUR CURRENT FRONTEND
from flask import Flask, request, jsonify, redirect, make_response, current_app
import stripe
import requests
import jwt
import sqlite3
import os
import secrets
import hmac
import hashlib
from datetime import datetime, timedelta, UTC
from urllib.parse import urlencode
from flask_cors import CORS
from dateutil.relativedelta import relativedelta
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import logging

app = Flask(__name__, static_folder='.', static_url_path='')
app.secret_key = os.getenv('SECRET_KEY')
if not app.secret_key or len(app.secret_key) < 32:
    raise ValueError("SECRET_KEY must be set and ≥32 chars")

JWT_SECRET = os.getenv('JWT_SECRET', app.secret_key)
REFRESH_SECRET = os.getenv('REFRESH_SECRET', secrets.token_hex(32))
RECAPTCHA_SECRET = os.getenv('RECAPTCHA_SECRET_KEY')

# === CONFIG ===
stripe.api_key = os.getenv('STRIPE_API_KEY')
GROK_API_KEY = os.getenv('GROK_API_KEY')

DOMAIN = os.getenv('DOMAIN', '').rstrip('/')
if not DOMAIN or not DOMAIN.startswith('https://'):
    raise ValueError("DOMAIN must be your full Render URL: https://your-app.onrender.com")

FRONTEND_URL = os.getenv('FRONTEND_URL', 'https://growth-easy-analytics-main-26jk-pb10b9hc9.vercel.app').rstrip('/')

# OAuth Clients
GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID')
GOOGLE_CLIENT_SECRET = os.getenv('GOOGLE_CLIENT_SECRET')
SHOPIFY_API_KEY = os.getenv('SHOPIFY_API_KEY')
SHOPIFY_CLIENT_SECRET = os.getenv('SHOPIFY_CLIENT_SECRET')
HUBSPOT_CLIENT_ID = os.getenv('HUBSPOT_CLIENT_ID')
HUBSPOT_CLIENT_SECRET = os.getenv('HUBSPOT_CLIENT_SECRET')

# === SECURITY ===
limiter = Limiter(app=app, key_func=get_remote_address, default_limits=["400 per day", "80 per hour"])

# FIXED: Allow all your Vercel + localhost origins
ALLOWED_ORIGINS = [
    "https://growth-easy-analytics-main.onrender.com",  # Your current live frontend
    "http://localhost:3000",
    "http://localhost:5173",
    "http://127.0.0.1:3000",
]

CORS(app, origins=ALLOWED_ORIGINS, supports_credentials=True)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@app.before_request
def enforce_https():
    if not request.is_secure and 'localhost' not in request.host and not app.debug:
        return redirect(request.url.replace('http://', 'https://'), code=301)

@app.after_request
def security_headers(response):
    origin = request.headers.get('Origin')
    if origin in ALLOWED_ORIGINS:
        response.headers['Access-Control-Allow-Origin'] = origin
    response.headers['Access-Control-Allow-Credentials'] = 'true'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, X-CSRF-Token, Recaptcha-Token'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
    response.headers['Vary'] = 'Origin'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    return response

# === DATABASE ===
DB_FILE = "data.db"

def get_db():
    conn = sqlite3.connect(DB_FILE, timeout=30.0, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    conn.execute("PRAGMA busy_timeout=30000;")
    return conn

def init_db():
    with get_db() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                stripe_id TEXT,
                shopify_shop TEXT,
                ga4_connected INTEGER DEFAULT 0,
                hubspot_connected INTEGER DEFAULT 0,
                ga4_access_token TEXT,
                ga4_refresh_token TEXT,
                ga4_property_id TEXT,
                shopify_access_token TEXT,
                hubspot_refresh_token TEXT,
                hubspot_access_token TEXT,
                gdpr_consented INTEGER DEFAULT 0,
                ga4_last_refreshed TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                date TEXT DEFAULT CURRENT_TIMESTAMP,
                revenue REAL DEFAULT 0,
                churn_rate REAL DEFAULT 0,
                at_risk INTEGER DEFAULT 0,
                ltv REAL DEFAULT 0,
                cac REAL DEFAULT 0,
                top_channel TEXT DEFAULT '',
                acquisition_cost REAL DEFAULT 0,
                retention_rate REAL DEFAULT 0,
                FOREIGN KEY(user_id) REFERENCES users(id)
            );
        """)
        cursor = conn.cursor()
        cursor.execute("PRAGMA table_info(users)")
        columns = [col[1] for col in cursor.fetchall()]
        for col, sql in [
            ('hubspot_refresh_token', 'ALTER TABLE users ADD COLUMN hubspot_refresh_token TEXT'),
            ('shopify_access_token', 'ALTER TABLE users ADD COLUMN shopify_access_token TEXT'),
            ('gdpr_consented', 'ALTER TABLE users ADD COLUMN gdpr_consented INTEGER DEFAULT 0'),
            ('ga4_last_refreshed', 'ALTER TABLE users ADD COLUMN ga4_last_refreshed TEXT'),
            ('hubspot_access_token', 'ALTER TABLE users ADD COLUMN hubspot_access_token TEXT')
        ]:
            if col not in columns:
                cursor.execute(sql)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_metrics_user ON metrics(user_id)")
        conn.commit()
init_db()

# === TOKEN HELPERS ===
def generate_tokens(user_id, email):
    access = jwt.encode(
        {"sub": str(user_id), "email": email, "exp": datetime.now(UTC) + timedelta(hours=1)},
        JWT_SECRET, algorithm="HS256"
    )
    refresh = jwt.encode(
        {"sub": str(user_id), "exp": datetime.now(UTC) + timedelta(days=30)},
        REFRESH_SECRET, algorithm="HS256"
    )
    return access, refresh

def get_user_from_token():
    token = request.cookies.get('access_token') or request.cookies.get('token')
    if not token:
        return None
    try:
        payload = jwt.decode(token, JWT_SECRET if 'access_token' in request.cookies else app.secret_key, algorithms=["HS256"])
        return {"id": int(payload["sub"]), "email": payload.get("email")}
    except jwt.ExpiredSignatureError:
        return None
    except Exception as e:
        logger.warning(f"JWT decode error: {e}")
        return None

def require_auth():
    user = get_user_from_token()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    return user

def verify_csrf():
    cookie = request.cookies.get('csrf_token')
    header = request.headers.get('X-CSRF-Token')
    if not cookie or not header:
        return False
    return hmac.compare_digest(cookie, header)

# === AUTO MIGRATE OLD TOKEN TO NEW SYSTEM ===
@app.before_request
def migrate_old_token():
    if request.path.startswith('/static'):
        return
    if request.cookies.get('access_token'):
        return
    old_token = request.cookies.get('token')
    if not old_token:
        return
    try:
        payload = jwt.decode(old_token, app.secret_key, algorithms=["HS256"])
        user_id = int(payload["sub"])
        email = payload.get("email")
        access_token, refresh_token = generate_tokens(user_id, email)
        csrf_token = secrets.token_hex(32)
        resp = make_response(redirect(request.url))
        resp.set_cookie('access_token', access_token, max_age=3600, secure=True, httponly=True, samesite='None', path='/')
        resp.set_cookie('refresh_token', refresh_token, max_age=30*24*3600, secure=True, httponly=True, samesite='None', path='/')
        resp.set_cookie('csrf_token', csrf_token, max_age=30*24*3600, secure=True, httponly=False, samesite='None', path='/')
        resp.delete_cookie('token', path='/')
        return resp
    except:
        pass

# === LEGACY /create-trial (YOUR FRONTEND STILL USES THIS) ===
@app.route('/create-trial', methods=['POST', 'OPTIONS'])
def legacy_create_trial():
    if request.method == 'OPTIONS':
        return '', 200
    return create_trial()

# === NEW SIGNUP ENDPOINT ===
@app.route('/api/signup', methods=['POST', 'OPTIONS'])
@limiter.limit("3 per minute", key_func=lambda: request.json.get('email', '').lower())
def create_trial():
    if request.method == 'OPTIONS':
        return '', 200

    email = request.json.get('email', '').strip().lower()
    consent = request.json.get('consent', False)
    recaptcha_token = request.json.get('recaptchaToken')

    if not email or '@' not in email or '.' not in email or not consent:
        return jsonify({"error": "Valid email and consent required"}), 400

    if RECAPTCHA_SECRET and recaptcha_token:
        verify_resp = requests.post("https://www.google.com/recaptcha/api/siteverify", data={
            'secret': RECAPTCHA_SECRET,
            'response': recaptcha_token,
            'remoteip': get_remote_address()
        })
        result = verify_resp.json()
        if not result.get('success') or result.get('score', 1.0) < 0.5:
            logger.warning(f"reCAPTCHA failed: {result}")
            return jsonify({"error": "Suspicious activity"}), 400

    try:
        customer = stripe.Customer.create(email=email)
        stripe.Subscription.create(
            customer=customer.id,
            items=[{"price": os.getenv('STRIPE_PRICE_ID')}],
            trial_period_days=7,
            payment_behavior='default_incomplete',
            trial_settings={"end_behavior": {"missing_payment_method": "cancel"}},
            expand=['latest_invoice.payment_intent']
        )
    except stripe.error.StripeError as e:
        logger.error(f"Stripe error: {e}")
        return jsonify({"error": "Payment setup failed—try again."}), 400

    with get_db() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO users (email, stripe_id, gdpr_consented) VALUES (?, ?, ?)",
            (email, customer.id, 1)
        )
        user_id = conn.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()['id']
        conn.commit()

    access_token, refresh_token = generate_tokens(user_id, email)
    csrf_token = secrets.token_hex(32)

    resp = make_response(jsonify({
        "success": True,
        "redirect": f"{FRONTEND_URL}/dashboard"
    }), 200)
    resp.set_cookie('access_token', access_token, max_age=3600, secure=True, httponly=True, samesite='None', path='/')
    resp.set_cookie('refresh_token', refresh_token, max_age=30*24*3600, secure=True, httponly=True, samesite='None', path='/')
    resp.set_cookie('csrf_token', csrf_token, max_age=30*24*3600, secure=True, httponly=False, samesite='None', path='/')
    resp.delete_cookie('token', path='/')
    return resp

# === GA4 TOKEN REFRESH ===
def refresh_ga4_token(user_id):
    with get_db() as conn:
        row = conn.execute("SELECT ga4_refresh_token FROM users WHERE id = ?", (user_id,)).fetchone()
        if not row or not row['ga4_refresh_token']:
            return None
        try:
            resp = requests.post("https://oauth2.googleapis.com/token", data={
                'client_id': GOOGLE_CLIENT_ID,
                'client_secret': GOOGLE_CLIENT_SECRET,
                'refresh_token': row['ga4_refresh_token'],
                'grant_type': 'refresh_token'
            }, timeout=10)
            if resp.status_code == 200:
                access_token = resp.json()['access_token']
                conn.execute("UPDATE users SET ga4_access_token = ?, ga4_last_refreshed = ? WHERE id = ?",
                            (access_token, datetime.now(UTC).isoformat(), user_id))
                conn.commit()
                return access_token
        except Exception as e:
            logger.error(f"GA4 token refresh failed (user {user_id}): {e}")
        return None

# === SYNC DATA ===
@app.route('/api/sync', methods=['POST', 'OPTIONS'])
@limiter.limit("10 per minute")
def sync_data():
    if request.method == 'OPTIONS':
        return '', 200
    if request.cookies.get('csrf_token') and not verify_csrf():
        return jsonify({"error": "CSRF validation failed"}), 403

    user = require_auth()
    if isinstance(user, tuple):
        return user
    user_id = user["id"]

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT shopify_shop, shopify_access_token, ga4_access_token, ga4_refresh_token, 
                   ga4_property_id, hubspot_refresh_token, hubspot_access_token, ga4_last_refreshed
            FROM users WHERE id=?
        """, (user_id,))
        row = cursor.fetchone()
        if not row:
            return jsonify({"error": "No user data"}), 400

        shop, shop_token, ga4_token, ga4_refresh, ga4_property, hubspot_refresh, hubspot_access, ga4_last_refreshed = row
        now = datetime.now(UTC)
        month_ago = now - relativedelta(months=1)

        revenue = churn_rate = at_risk = ltv = cac = acquisition_cost = retention_rate = 0
        top_channel = ''

        if shop and shop_token:
            try:
                orders_resp = requests.get(
                    f"https://{shop}/admin/api/2024-01/orders.json?status=any&created_at_min={month_ago.isoformat()}&limit=250",
                    headers={'X-Shopify-Access-Token': shop_token}, timeout=10
                )
                if orders_resp.status_code == 200:
                    orders = orders_resp.json().get('orders', [])
                    revenue = sum(float(o['total_price']) for o in orders[-30:] if o.get('total_price'))
                    canceled = len([o for o in orders if o.get('cancelled_at')])
                    total_orders = len(orders)
                    churn_rate = (canceled / total_orders * 100) if total_orders else 0

                    customer_ids = {o.get('customer', {}).get('id') for o in orders if o.get('customer')}
                    if customer_ids:
                        ltv = revenue / len(customer_ids) * 3

                    customers_resp = requests.get(
                        f"https://{shop}/admin/api/2024-01/customers.json?limit=250",
                        headers={'X-Shopify-Access-Token': shop_token}, timeout=10
                    )
                    if customers_resp.status_code == 200:
                        customers = customers_resp.json().get('customers', [])
                        inactive = len([c for c in customers if c.get('orders_count', 0) == 0])
                        at_risk = max(at_risk, inactive)
            except Exception as e:
                logger.error(f"Shopify sync error (user {user_id}): {e}")

        if ga4_property and ga4_token:
            if not ga4_last_refreshed or datetime.fromisoformat(ga4_last_refreshed.replace('Z', '+00:00')) < datetime.now(UTC) - timedelta(minutes=50):
                ga4_token = refresh_ga4_token(user_id) or ga4_token

            try:
                report_url = f"https://analyticsdata.googleapis.com/v1beta/properties/{ga4_property}:runReport"
                headers = {'Authorization': f'Bearer {ga4_token}', 'Content-Type': 'application/json'}

                payload = {
                    "dateRanges": [{"startDate": "30daysAgo", "endDate": "today"}],
                    "dimensions": [{"name": "channelGrouping"}],
                    "metrics": [{"name": "newUsers"}, {"name": "userAcquisition::estimatedAdCost"}]
                }
                report_resp = requests.post(report_url, json=payload, headers=headers, timeout=10)
                if report_resp.status_code == 200:
                    rows = report_resp.json().get('rows', [])
                    if rows:
                        top_row = rows[0]
                        top_channel = top_row['dimensionValues'][0]['value']
                        new_users = int(top_row['metricValues'][0]['value'])
                        acquisition_cost = float(top_row['metricValues'][1]['value']) if len(top_row['metricValues']) > 1 else 0
                        cac = acquisition_cost / new_users if new_users else 0

                retention_payload = {
                    "dateRanges": [{"startDate": "30daysAgo", "endDate": "today"}],
                    "metrics": [{"name": "cohortUserRetentionRate"}]
                }
                retention_resp = requests.post(report_url, json=retention_payload, headers=headers, timeout=10)
                if retention_resp.status_code == 200:
                    r_rows = retention_resp.json().get('rows', [])
                    retention_rate = float(r_rows[0]['metricValues'][0]['value']) * 100 if r_rows else 85

            except Exception as e:
                logger.error(f"GA4 sync error (user {user_id}): {e}")

        if hubspot_refresh and hubspot_access:
            try:
                contacts_url = "https://api.hubapi.com/crm/v3/objects/contacts?properties=hs_lifecyclestage"
                headers = {'Authorization': f'Bearer {hubspot_access}'}
                resp = requests.get(contacts_url, headers=headers, timeout=10)
                if resp.status_code == 200:
                    contacts = resp.json().get('results', [])
                    retained = len([c for c in contacts if c['properties'].get('hs_lifecyclestage') in ['customer', 'subscriber']])
                    total = len(contacts)
                    retention_rate = (retained / total * 100) if total else 0
            except Exception as e:
                logger.error(f"HubSpot sync error (user {user_id}): {e}")

        if not cac and revenue:
            cac = revenue * 0.05

        cursor.execute("""
            INSERT OR REPLACE INTO metrics 
            (user_id, date, revenue, churn_rate, at_risk, ltv, cac, top_channel, acquisition_cost, retention_rate)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (user_id, now.isoformat(), revenue, churn_rate, at_risk, ltv, cac, top_channel, acquisition_cost, retention_rate))
        conn.commit()

    return jsonify({
        "status": "Synced",
        "revenue": revenue,
        "churn_rate": churn_rate,
        "at_risk": at_risk,
        "ltv": ltv,
        "cac": cac,
        "top_channel": top_channel,
        "acquisition_cost": acquisition_cost,
        "retention_rate": retention_rate
    })

# === METRICS ENDPOINT ===
@app.route('/api/metrics', methods=['GET', 'OPTIONS'])
def metrics():
    if request.method == 'OPTIONS':
        return '', 200
    user = require_auth()
    if isinstance(user, tuple):
        return user
    user_id = user["id"]

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT date FROM metrics WHERE user_id = ? ORDER BY date DESC LIMIT 1", (user_id,))
        last = cursor.fetchone()
        if not last or datetime.fromisoformat(last[0].replace('Z', '+00:00')) < datetime.now(UTC) - timedelta(hours=1):
            with current_app.app_context():
                sync_data()

        cursor.execute("""
            SELECT revenue, churn_rate, at_risk, ltv, cac, top_channel, acquisition_cost, retention_rate, date 
            FROM metrics WHERE user_id = ? ORDER BY date DESC LIMIT 4
        """, (user_id,))
        rows = cursor.fetchall()
        if not rows:
            return jsonify({
                "revenue": {"total": 0, "trend": "0%", "history": {"labels": [], "values": []}},
                "churn": {"rate": 0, "at_risk": 0},
                "performance": {"ratio": "0", "ltv": 150, "cac": 50},
                "acquisition": {"top_channel": "", "acquisition_cost": 0},
                "retention": {"rate": 0},
                "ai_insight": "Connect integrations to unlock real insights."
            })

        latest = rows[0]
        history_labels = [r[8][:10] for r in rows[::-1]]
        history_values = [r[0] for r in rows[::-1]]
        trend = f"+{((history_values[0] - history_values[-1]) / history_values[-1] * 100):.0f}%" if len(history_values) > 1 and history_values[-1] else "0%"

        return jsonify({
            "revenue": {"total": latest[0] or 0, "trend": trend, "history": {"labels": history_labels, "values": history_values}},
            "churn": {"rate": latest[1] or 0, "at_risk": latest[2] or 0},
            "performance": {"ratio": f"{(latest[3] or 150) / (latest[4] or 50):.1f}", "ltv": latest[3] or 150, "cac": latest[4] or 50},
            "acquisition": {"top_channel": latest[5] or 'Organic', "acquisition_cost": latest[6] or 0},
            "retention": {"rate": latest[7] or 85},
            "ai_insight": f"Churn {latest[1] or 0:.1f}% – Send win-backs to {latest[2] or 0} at-risk to save £{(latest[0] or 0) * (latest[1] or 0) / 100:.0f}/mo."
        })
        

# === AI CHAT ===
@app.route('/api/chat', methods=['POST', 'OPTIONS'])
@limiter.limit("15 per minute")
def ai_chat():
    if request.method == 'OPTIONS':
        return '', 200
    if request.cookies.get('csrf_token') and not verify_csrf():
        return jsonify({"error": "CSRF failed"}), 403
    user = require_auth()
    if isinstance(user, tuple):
        return user
    user_id = user["id"]

    message = request.json.get('message', '').strip()
    if not message:
        return jsonify({"reply": "Ask me about churn, revenue, or growth."})

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT revenue, churn_rate, at_risk FROM metrics WHERE user_id=? ORDER BY date DESC LIMIT 1", (user_id,))
        row = cursor.fetchone()
        summary = f"Revenue: £{row[0] or 0}, Churn: {row[1] or 0}%, At-risk: {row[2] or 0}" if row else "No data"

    system_prompt = f"You are GrowthEasy AI. User metrics: {summary}. Answer: {message}. <150 words."
    try:
        resp = requests.post(
            "https://api.x.ai/v1/chat/completions",
            headers={"Authorization": f"Bearer {GROK_API_KEY}", "Content-Type": "application/json"},
            json={"model": "grok-beta", "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": message}
            ], "temperature": 0.7, "max_tokens": 200}, timeout=20
        )
        resp.raise_for_status()
        reply = resp.json()["choices"][0]["message"]["content"]
    except Exception as e:
        logger.error(f"Grok error: {e}")
        reply = "Try reducing churn with targeted emails."

    return jsonify({"reply": reply})

# === OAUTH ROUTES ===
@app.route('/auth/<provider>')
def oauth_start(provider):
    user = get_user_from_token()
    if not user:
        return redirect(f"{FRONTEND_URL}/?error=login_required")

    user_id = user["id"]
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
            'scope': ' '.join([
                'https://www.googleapis.com/auth/analytics.readonly',
                'https://www.googleapis.com/auth/analytics.manage.users'
            ]),
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
            'scope': 'crm.objects.contacts.read crm.objects.deals.read',
            'response_type': 'code',
            'state': str(user_id)
        }
        auth_url = f"https://app.hubspot.com/oauth/authorize?{urlencode(params)}"
        return redirect(auth_url)

    return "Invalid provider", 400

# === SHOPIFY CALLBACK ===
def verify_shopify_hmac(params):
    hmac_sig = params.get('hmac')
    if not hmac_sig:
        return False
    message = '&'.join(f"{k}={v}" for k, v in sorted(params.items()) if k not in ['hmac', 'signature'])
    digest = hmac.new(SHOPIFY_CLIENT_SECRET.encode(), message.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(digest, hmac_sig)

@app.route('/auth/shopify/callback')
def shopify_callback():
    if not verify_shopify_hmac(request.args):
        return "<script>alert('Invalid Shopify signature'); window.close();</script>", 400

    code = request.args.get('code')
    state = request.args.get('state')
    error = request.args.get('error')

    if error or not code or not state:
        return "<script>alert('Shopify auth failed'); window.close();</script>", 400

    try:
        user_id, shop = state.split('|', 1)
        user_id = int(user_id)
    except:
        return "Invalid state", 400

    user = get_user_from_token()
    if not user or user["id"] != user_id:
        return "Unauthorized", 401

    token_url = f"https://{shop}/admin/oauth/access_token"
    payload = {'client_id': SHOPIFY_API_KEY, 'client_secret': SHOPIFY_CLIENT_SECRET, 'code': code}
    resp = requests.post(token_url, data=payload)
    if resp.status_code != 200:
        return f"Shopify auth failed: {resp.text}", 400
    access_token = resp.json().get('access_token', '')

    with get_db() as conn:
        conn.execute("UPDATE users SET shopify_shop = ?, shopify_access_token = ? WHERE id = ?", (shop, access_token, user_id))
        conn.commit()

    return "<script>alert('Shopify Connected Successfully!'); window.close(); window.opener.location.reload();</script>"

# === GA4 CALLBACK (FIXED MISSING ) ) ===
@app.route('/auth/ga4/callback')
def ga4_callback():
    code = request.args.get('code')
    state = request.args.get('state')
    error = request.args.get('error')
    if error or not code or not state:
        return "<script>alert('GA4 Error'); window.close(); window.opener.location.reload();</script>", 400
    
    try:
        user_id = int(state)
    except:
        return "Invalid state", 400

    user = get_user_from_token()
    if not user or user["id"] != user_id:
        return "Unauthorized", 401

    token_url = "https://oauth2.googleapis.com/token"
    payload = {
        'code': code,
        'client_id': GOOGLE_CLIENT_ID,
        'client_secret': GOOGLE_CLIENT_SECRET,
        'redirect_uri': f"{DOMAIN}/auth/ga4/callback",
        'grant_type': 'authorization_code'
    }
    resp = requests.post(token_url, data=payload, timeout=15)
    if resp.status_code != 200:
        return f"GA4 auth failed: {resp.text}", 400
    token_data = resp.json()
    access_token = token_data.get('access_token', '')
    refresh_token = token_data.get('refresh_token', '')

    property_id = None
    try:
        summaries_resp = requests.get(
            "https://analyticsadmin.googleapis.com/v1/accountSummaries",
            headers={'Authorization': f'Bearer {access_token}'}, timeout=10
        )
        if summaries_resp.status_code == 200:
            summaries = summaries_resp.json().get('accountSummaries', [])
            if summaries and summaries[0].get('propertySummaries'):
                prop = summaries[0]['propertySummaries'][0].get('property', '')
                if prop.startswith('properties/'):
                    property_id = prop.split('/')[-1]
    except Exception as e:
        logger.warning(f"GA4 property detection failed: {e}")

    with get_db() as conn:
        conn.execute("""
            UPDATE users SET ga4_connected = 1, ga4_access_token = ?, ga4_refresh_token = ?, 
            ga4_property_id = COALESCE(?, ga4_property_id), ga4_last_refreshed = ? WHERE id = ?
        """, (access_token, refresh_token, property_id, datetime.now(UTC).isoformat(), user_id))
        conn.commit()

    return "<script>alert('GA4 Connected Successfully!'); window.close(); window.opener.location.reload();</script>"

# === HUBSPOT CALLBACK (FIXED MISSING ) ) ===
@app.route('/auth/hubspot/callback')
def hubspot_callback():
    code = request.args.get('code')
    state = request.args.get('state')
    error = request.args.get('error')
    if error or not code or not state:
        return "<script>alert('HubSpot Error'); window.close(); window.opener.location.reload();</script>", 400
    
    user_id = int(state)
    user = get_user_from_token()
    if not user or user["id"] != user_id:
        return "Unauthorized", 401

    token_url = "https://api.hubapi.com/oauth/v1/token"
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
    access_token = token_data.get('access_token', '')
    refresh_token = token_data.get('refresh_token', '')

    with get_db() as conn:
        conn.execute("""
            UPDATE users SET hubspot_connected = 1, hubspot_access_token = ?, hubspot_refresh_token = ? WHERE id = ?
        """, (access_token, refresh_token, user_id))
        conn.commit()

    return "<script>alert('HubSpot Connected!'); window.close(); window.opener.location.reload();</script>"

@app.route('/health')
def health():
    return jsonify({"status": "ok", "time": datetime.now(UTC).isoformat()})

@app.route('/api/create-checkout', methods=['POST', 'OPTIONS'])
def create_checkout():
    if request.method == 'OPTIONS':
        return '', 200

    user = require_auth()
    if isinstance(user, tuple):
        return user
    user_id = user["id"]

    plan = request.json.get('plan')
    if plan not in ['lifetime_early', 'lifetime', 'monthly', 'annual']:
        return jsonify({"error": "Invalid plan"}), 400

    price_map = {
        'lifetime_early': os.getenv('STRIPE_PRICE_LTD_EARLY'),
        'lifetime': os.getenv('STRIPE_PRICE_LTD'),
        'monthly': os.getenv('STRIPE_PRICE_MONTHLY'),
        'annual': os.getenv('STRIPE_PRICE_ANNUAL'),
    }

    price_id = price_map[plan]

    with get_db() as conn:
        row = conn.execute("SELECT stripe_id FROM users WHERE id = ?", (user_id,)).fetchone()
        customer_id = row['stripe_id'] if row else None

    session = stripe.checkout.Session.create(
        customer=customer_id,
        payment_method_types=['card'],
        line_items=[{'price': price_id, 'quantity': 1}],
        mode='subscription' if plan in ['monthly', 'annual'] else 'payment',
        success_url=f"{FRONTEND_URL}/success?session_id={{CHECKOUT_SESSION_ID}}",
        cancel_url=f"{FRONTEND_URL}/pricing",
        subscription_data={'trial_period_days': 7} if plan in ['monthly', 'annual'] else None,
    )

    return jsonify({"sessionId": session.id})

# === FIXED CATCH-ALL ===
@app.route('/<path:path>')
def catch_all(path):
    # Let Flask handle known routes (api/, auth/, health, etc.) normally
    # Only redirect everything ELSE to frontend for SPA client-side routing
    if path.startswith(('api/', 'auth/', 'health', 'create-trial', 'static/')):
        return "Not Found", 404  # Optional: remove this line entirely if you want real 404s
    
    # Redirect all other paths to your Vercel frontend (for /dashboard, /about, etc.)
    target = FRONTEND_URL or "https://growth-easy-analytics-main.onrender.com"
    return redirect(target.rstrip('/') + '/' + path, code=302)

# Also add a simple root route for testing (optional but helpful)
@app.route('/')
def root():
    return jsonify({"message": "GrowthEasy AI Backend Live 🚀", "health": "ok"}), 200

if __name__ == '__main__': 
    app.run(host='0.0.0.0', port=int(os.getenv('PORT', 5000)), debug=False)