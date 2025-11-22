from flask import Flask, request, jsonify, redirect
import stripe
import requests
import jwt
import sqlite3
import os
from datetime import datetime, timedelta
from urllib.parse import urlencode
from flask_cors import CORS
from dateutil.relativedelta import relativedelta
import logging

app = Flask(__name__, static_folder='.', static_url_path='')
app.secret_key = os.getenv('SECRET_KEY')

# === CONFIG ===
stripe.api_key = os.getenv('STRIPE_API_KEY')
GROK_API_KEY = os.getenv('GROK_API_KEY')
DOMAIN = os.getenv('DOMAIN', '').rstrip('/')

# OAuth Clients
GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID')
GOOGLE_CLIENT_SECRET = os.getenv('GOOGLE_CLIENT_SECRET')
SHOPIFY_API_KEY = os.getenv('SHOPIFY_API_KEY')
SHOPIFY_CLIENT_SECRET = os.getenv('SHOPIFY_CLIENT_SECRET')
HUBSPOT_CLIENT_ID = os.getenv('HUBSPOT_CLIENT_ID')
HUBSPOT_CLIENT_SECRET = os.getenv('HUBSPOT_CLIENT_SECRET')

FRONTEND_URL = os.getenv('FRONTEND_URL', 'https://growth-easy-analytics-main-26jk-pb10b9hc9.vercel.app').rstrip('/')

# === CORS & LOGGING ===
ALLOWED_ORIGINS = [
    FRONTEND_URL,
    DOMAIN,
    "https://growth-easy-analytics-main-26jk-pb10b9hc9.vercel.app",
    "https://growth-easy-analytics-main-26jk-seanwoodwood003-engs-projects.vercel.app",
    "https://s-main-26jk-ns9wjk1s.vercel.app",
    "https://main-26jk-838h89s0h.vercel.app"
]

CORS(
    app,
    origins=ALLOWED_ORIGINS,
    supports_credentials=True,
    methods=['GET', 'POST', 'OPTIONS'],
    allow_headers=['Content-Type', 'Authorization']
)

logging.basicConfig(level=logging.INFO)
logging.info(f"CORS origins configured: {ALLOWED_ORIGINS}")

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
                ga4_property_id TEXT,
                shopify_access_token TEXT,
                hubspot_refresh_token TEXT,
                hubspot_access_token TEXT,
                gdpr_consented INTEGER DEFAULT 0,
                ga4_last_refreshed TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
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

        conn.execute("""
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
            )
        """)
        conn.commit()
init_db()

# === AUTH HELPERS ===
def get_user_from_token():
    token = request.cookies.get('token')
    if not token:
        return None
    try:
        payload = jwt.decode(token, app.secret_key, algorithms=["HS256"])
        return {"id": int(payload["sub"]), "email": payload.get("email")}
    except Exception as e:
        logging.warning(f"JWT decode error: {e}")
        return None

def require_auth():
    user = get_user_from_token()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    return user

# === ROUTES ===
@app.route('/')
def index():
    return redirect(FRONTEND_URL)

# === SIGNUP + STRIPE TRIAL ===
@app.route('/create-trial', methods=['POST', 'OPTIONS'])
def create_trial():
    if request.method == 'OPTIONS':
        return '', 200
    email = request.json.get('email', '').strip().lower()
    consent = request.json.get('consent', False)
    if not email or '@' not in email or '.' not in email or not consent:
        return jsonify({"error": "Valid email and consent required"}), 400

    try:
        customer = stripe.Customer.create(email=email)
        stripe.Subscription.create(
            customer=customer.id,
            items=[{"price": os.getenv('STRIPE_PRICE_ID')}],
            trial_period_days=7
        )
    except stripe.error.StripeError as e:
        error_msg = getattr(e, 'user_message', str(e)) if hasattr(e, 'user_message') else f'StripeError: {e.__class__.__name__}'
        logging.error(f"Stripe error for email {email}: {error_msg}")
        return jsonify({"error": "Payment setup failed—try again."}), 400

    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT OR IGNORE INTO users (email, stripe_id, gdpr_consented) VALUES (?, ?, ?)",
            (email, customer.id, 1)
        )
        conn.commit()
        user_id = cursor.lastrowid or cursor.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()[0]

    token = jwt.encode(
        {"sub": str(user_id), "email": email, "exp": datetime.utcnow() + timedelta(days=7)},
        app.secret_key, algorithm="HS256"
    )

    return jsonify({
        "success": True,
        "token": token,
        "redirect": f"{FRONTEND_URL}/index.html"
    }), 200

# === DATA SYNC ===
@app.route('/api/sync', methods=['POST', 'OPTIONS'])
def sync_data():
    if request.method == 'OPTIONS':
        return '', 200
    user = require_auth()
    if isinstance(user, tuple):
        return user
    user_id = user["id"]

    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT shopify_shop, shopify_access_token, ga4_access_token, ga4_refresh_token, 
                   ga4_property_id, hubspot_refresh_token, hubspot_access_token
            FROM users WHERE id=?
        """, (user_id,))
        row = cursor.fetchone()
        if not row:
            return jsonify({"error": "No user data"}), 400

        shop, shop_token, ga4_token, ga4_refresh, ga4_property, hubspot_refresh, hubspot_access = row
        now = datetime.utcnow()
        month_ago = now - relativedelta(months=1)

        revenue = churn_rate = at_risk = ltv = cac = acquisition_cost = retention_rate = 0
        top_channel = ''

        # === SHOPIFY ===
        if shop and shop_token:
            try:
                orders_resp = requests.get(
                    f"https://{shop}/admin/api/2024-01/orders.json?status=any&created_at_min={month_ago.isoformat()}&limit=250",
                    headers={'X-Shopify-Access-Token': shop_token}, timeout=10
                )
                if orders_resp.status_code == 200:
                    orders = orders_resp.json().get('orders', [])
                    revenue = sum(float(o['total_price']) for o in orders[-30:])
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
                logging.error(f"Shopify sync error (user {user_id}): {e}")

        # === GA4 ===
        if ga4_property and ga4_token:
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
                logging.error(f"GA4 sync error (user {user_id}): {e}")

        # === HUBSPOT ===
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
                logging.error(f"HubSpot sync error (user {user_id}): {e}")

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

# === METRICS ===
@app.route('/api/metrics', methods=['GET', 'OPTIONS'])
def metrics():
    if request.method == 'OPTIONS':
        return '', 200
    user = require_auth()
    if isinstance(user, tuple):
        return user
    user_id = user["id"]

    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT date FROM metrics WHERE user_id = ? ORDER BY date DESC LIMIT 1", (user_id,))
        last = cursor.fetchone()
        if not last or datetime.fromisoformat(last[0]) < datetime.utcnow() - timedelta(hours=1):
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
def ai_chat():
    if request.method == 'OPTIONS':
        return '', 200
    user = require_auth()
    if isinstance(user, tuple):
        return user
    user_id = user["id"]

    message = request.json.get('message', '').strip()
    if not message:
        return jsonify({"reply": "Ask me about churn, revenue, or growth."})

    with sqlite3.connect(DB_FILE) as conn:
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
        logging.error(f"Grok error: {e}")
        reply = "Try reducing churn with targeted emails."

    return jsonify({"reply": reply})

# === OAUTH START ===
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

# === OAUTH CALLBACKS — ONLY RETURN LINES CHANGED ===
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

    user = get_user_from_token()
    if not user or user["id"] != user_id:
        return "Unauthorized", 401

    token_url = f"https://{shop}/admin/oauth/access_token"
    payload = {'client_id': SHOPIFY_API_KEY, 'client_secret': SHOPIFY_CLIENT_SECRET, 'code': code}
    resp = requests.post(token_url, data=payload)
    if resp.status_code != 200:
        return "Shopify auth failed", 400
    access_token = resp.json().get('access_token', '')

    with sqlite3.connect(DB_FILE) as conn:
        conn.execute("UPDATE users SET shopify_shop = ?, shopify_access_token = ? WHERE id = ?", (shop, access_token, user_id))
        conn.commit()

    sync_data()
    return f"<script>window.location.href = '{FRONTEND_URL}/index.html?connected=shopify'</script>"

@app.route('/auth/ga4/callback')
def ga4_callback():
    code = request.args.get('code')
    state = request.args.get('state')
    if not code or not state:
        return "Missing code or state", 400

    user_id = int(state)
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
    resp = requests.post(token_url, data=payload)
    if resp.status_code != 200:
        return "GA4 auth failed", 400
    token_data = resp.json()
    access_token = token_data.get('access_token', '')
    refresh_token = token_data.get('refresh_token', '')

    property_id = ''
    try:
        admin_url = "https://analyticsadmin.googleapis.com/v1beta/properties"
        props_resp = requests.get(admin_url, headers={'Authorization': f'Bearer {access_token}'})
        if props_resp.status_code == 200 and props_resp.json().get('properties'):
            property_id = props_resp.json()['properties'][0]['name'].split('/')[-1]
    except:
        pass

    with sqlite3.connect(DB_FILE) as conn:
        conn.execute("""
            UPDATE users SET ga4_connected = 1, ga4_access_token = ?, ga4_refresh_token = ?, 
            ga4_property_id = ?, ga4_last_refreshed = ? WHERE id = ?
        """, (access_token, refresh_token, property_id, datetime.utcnow().isoformat(), user_id))
        conn.commit()

    sync_data()
    return f"<script>window.location.href = '{FRONTEND_URL}/index.html?connected=ga4'</script>"

@app.route('/auth/hubspot/callback')
def hubspot_callback():
    code = request.args.get('code')
    state = request.args.get('state')
    if not code or not state:
        return "Missing code or state", 400

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
        return "HubSpot auth failed", 400
    token_data = resp.json()
    access_token = token_data.get('access_token', '')
    refresh_token = token_data.get('refresh_token', '')

    with sqlite3.connect(DB_FILE) as conn:
        conn.execute("""
            UPDATE users SET hubspot_connected = 1, hubspot_access_token = ?, hubspot_refresh_token = ? WHERE id = ?
        """, (access_token, refresh_token, user_id))
        conn.commit()

    sync_data()
    return f"<script>window.location.href = '{FRONTEND_URL}/index.html?connected=hubspot'</script>"

@app.route('/health')
def health():
    return jsonify({"status": "ok", "time": datetime.utcnow().isoformat()})

# === CATCH-ALL ===
@app.route('/<path:path>', methods=['GET', 'POST', 'OPTIONS'])
def catch_all(path):
    if path.startswith('api/') or path.startswith('auth/'):
        return "Not Found", 404
    return redirect(FRONTEND_URL)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.getenv('PORT', 5000)), debug=False)