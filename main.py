# main.py — FINAL: STRIPE + SHOPIFY + HUBSPOT + GA4 (CREDENTIALS TO BE FILLED)
from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer
import stripe
import sqlite3
import requests
from jose import JWTError, jwt
from passlib.context import CryptContext
from datetime import datetime
from google_auth_oauthlib.flow import Flow

app = FastAPI()

# === CORS ===
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://growth-easy-analytics-main-eawl-5hokybna9.vercel.app",
        "https://growtheasy-ai.com"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)

# === CONFIG (FILL THESE LATER) ===
stripe.api_key = "sk_live_..."  # YOUR LIVE KEY
WEBHOOK_SECRET = "whsec_..."    # YOUR WEBHOOK SECRET
JWT_SECRET = "your-ultra-secure-jwt-secret-2025-change-this"
ALGORITHM = "HS256"
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()

DB_NAME = "users.db"
PRICE_ID = "price_1SQCnY5Hb29sHp3B1L7iQm2r"

# === SHOPIFY (ALREADY LIVE) ===
SHOPIFY_CLIENT_ID = "your-shopify-client-id"
SHOPIFY_SECRET = "your-shopify-secret"
SHOPIFY_REDIRECT = "https://growth-easy-analytics-2.onrender.com/auth/shopify/callback"

# === HUBSPOT (PASTE LATER) ===
HUBSPOT_CLIENT_ID = "PASTE_HUBSPOT_CLIENT_ID_HERE"
HUBSPOT_SECRET = "PASTE_HUBSPOT_CLIENT_SECRET_HERE"

# === GA4 (PASTE LATER) ===
GA4_CLIENT_ID = "PASTE_GA4_CLIENT_ID_HERE"
GA4_CLIENT_SECRET = "PASTE_GA4_CLIENT_SECRET_HERE"
GA4_REDIRECT_URI = "https://growth-easy-analytics-2.onrender.com/auth/ga4/callback"

# === DB INIT ===
def init_db():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE,
            password_hash TEXT,
            stripe_customer_id TEXT,
            subscription_id TEXT,
            status TEXT,
            trial_end TEXT,
            shopify_shop TEXT,
            shopify_token TEXT,
            hubspot_token TEXT,
            ga4_token TEXT,
            created_at TEXT
        )
    ''')
    conn.commit()
    conn.close()
init_db()

# === AUTH ===
def get_current_user(authorization: str = Depends(security)):
    try:
        token = authorization.credentials
        payload = jwt.decode(token, JWT_SECRET, algorithms=[ALGORITHM])
        return payload["user_id"]
    except JWTError:
        raise HTTPException(401, "Invalid token")

# === CREATE TRIAL ===
@app.post("/create-trial")
async def create_trial(request: Request):
    data = await request.json()
    email = data.get("email")
    if not email:
        raise HTTPException(400, "Email required")

    session = stripe.checkout.Session.create(
        mode='subscription',
        payment_method_types=['card'],
        customer_email=email,
        line_items=[{'price': PRICE_ID, 'quantity': 1}],
        success_url='https://growtheasy-ai.com/login.html',
        cancel_url='https://growtheasy-ai.com/signup.html',
        subscription_data={'trial_period_days': 7},
        payment_method_collection='required'
    )
    return {"url": session.url}

# === LOGIN ===
@app.post("/api/login")
async def login(request: Request):
    data = await request.json()
    email = data["email"]
    password = data["password"]

    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("SELECT id, password_hash FROM users WHERE email = ?", (email,))
    user = c.fetchone()
    conn.close()

    if user and pwd_context.verify(password, user[1]):
        token = jwt.encode({"user_id": user[0]}, JWT_SECRET, algorithm=ALGORITHM)
        return {"token": token}
    raise HTTPException(401, "Invalid credentials")

# === STRIPE WEBHOOK ===
@app.post("/webhook")
async def webhook(request: Request):
    payload = await request.body()
    sig = request.headers.get("stripe-signature")
    try:
        event = stripe.Webhook.construct_event(payload, sig, WEBHOOK_SECRET)
    except:
        raise HTTPException(400)

    if event['type'] == 'checkout.session.completed':
        session = event['data']['object']
        email = session['customer_details']['email']
        customer_id = session['customer']
        sub_id = session['subscription']
        trial_end = session.get('subscription_details', {}).get('trial_end')
        trial_end_str = datetime.fromtimestamp(trial_end).isoformat() if trial_end else None

        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        c.execute('''
            INSERT OR REPLACE INTO users 
            (email, stripe_customer_id, subscription_id, status, trial_end, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (email, customer_id, sub_id, 'trialing' if trial_end else 'active', trial_end_str, datetime.utcnow().isoformat()))
        conn.commit()
        conn.close()

    return {"status": "success"}

# === SHOPIFY OAUTH ===
@app.get("/auth/shopify")
def shopify_auth(shop: str):
    url = f"https://{shop}/admin/oauth/authorize?client_id={SHOPIFY_CLIENT_ID}&scope=read_orders,read_customers&redirect_uri={SHOPIFY_REDIRECT}"
    return RedirectResponse(url)

@app.get("/auth/shopify/callback")
async def shopify_callback(code: str, shop: str, user_id: int = Depends(get_current_user)):
    token_res = requests.post(f"https://{shop}/admin/oauth/access_token", data={
        "client_id": SHOPIFY_CLIENT_ID,
        "client_secret": SHOPIFY_SECRET,
        "code": code
    }).json()
    token = token_res.get("access_token")

    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("UPDATE users SET shopify_shop = ?, shopify_token = ? WHERE id = ?", (shop, token, user_id))
    conn.commit()
    conn.close()
    return RedirectResponse("/dashboard.html")

# === HUBSPOT OAUTH (WILL WORK ONCE CREDENTIALS ADDED) ===
@app.get("/auth/hubspot")
def hubspot_auth(user_id: int = Depends(get_current_user)):
    if HUBSPOT_CLIENT_ID == "PASTE_HUBSPOT_CLIENT_ID_HERE":
        return {"error": "HubSpot not configured"}
    redirect_uri = "https://growth-easy-analytics-2.onrender.com/auth/hubspot/callback"
    url = f"https://app.hubspot.com/oauth/authorize?client_id={HUBSPOT_CLIENT_ID}&redirect_uri={redirect_uri}&scope=contacts"
    return RedirectResponse(url)

@app.get("/auth/hubspot/callback")
async def hubspot_callback(code: str, user_id: int = Depends(get_current_user)):
    if HUBSPOT_CLIENT_ID == "PASTE_HUBSPOT_CLIENT_ID_HERE":
        return {"error": "HubSpot not configured"}
    res = requests.post("https://api.hubapi.com/auth/v1/oauth/tokens", data={
        "grant_type": "authorization_code",
        "client_id": HUBSPOT_CLIENT_ID,
        "client_secret": HUBSPOT_SECRET,
        "redirect_uri": "https://growth-easy-analytics-2.onrender.com/auth/hubspot/callback",
        "code": code
    }).json()
    token = res.get("access_token")
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("UPDATE users SET hubspot_token = ? WHERE id = ?", (token, user_id))
    conn.commit()
    conn.close()
    return RedirectResponse("/dashboard.html")

# === GA4 OAUTH (WILL WORK ONCE CREDENTIALS ADDED) ===
@app.get("/auth/ga4")
def ga4_auth(user_id: int = Depends(get_current_user)):
    if GA4_CLIENT_ID == "PASTE_GA4_CLIENT_ID_HERE":
        return {"error": "GA4 not configured"}
    flow = Flow.from_client_config(
        {
            "web": {
                "client_id": GA4_CLIENT_ID,
                "client_secret": GA4_CLIENT_SECRET,
                "redirect_uris": [GA4_REDIRECT_URI],
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token"
            }
        },
        scopes=['https://www.googleapis.com/auth/analytics.readonly']
    )
    auth_url, _ = flow.authorization_url(prompt='consent')
    return RedirectResponse(auth_url)

@app.get("/auth/ga4/callback")
async def ga4_callback(code: str, user_id: int = Depends(get_current_user)):
    if GA4_CLIENT_ID == "PASTE_GA4_CLIENT_ID_HERE":
        return {"error": "GA4 not configured"}
    flow = Flow.from_client_config(
        {
            "web": {
                "client_id": GA4_CLIENT_ID,
                "client_secret": GA4_CLIENT_SECRET,
                "redirect_uris": [GA4_REDIRECT_URI]
            }
        },
        scopes=['https://www.googleapis.com/auth/analytics.readonly']
    )
    flow.fetch_token(code=code)
    creds = flow.credentials
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("UPDATE users SET ga4_token = ? WHERE id = ?", (creds.token, user_id))
    conn.commit()
    conn.close()
    return RedirectResponse("/dashboard.html")

# === METRICS ===
@app.get("/api/metrics")
async def metrics(user_id: int = Depends(get_current_user)):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("SELECT shopify_token, shopify_shop, hubspot_token, ga4_token FROM users WHERE id = ?", (user_id,))
    row = c.fetchone()
    conn.close()

    if not row or not row[0]:
        return {"error": "Connect Shopify first"}

    token, shop, hubspot_token, ga4_token = row

    orders = requests.get(
        f"https://{shop}/admin/api/2024-10/orders.json?limit=250",
        headers={"X-Shopify-Access-Token": token}
    ).json().get("orders", [])

    cancelled = len([o for o in orders if o["financial_status"] == "voided"])
    total = len(orders)
    churn = round(cancelled / total * 100, 2) if total else 0
    revenue = sum(float(o["total_price"]) for o in orders if o["financial_status"] == "paid")

    return {
        "revenue": {"total": round(revenue, 2), "trend": "+12%"},
        "churn": {"rate": churn, "at_risk": cancelled},
        "ai_insight": f"{cancelled} at-risk. Send win-back email to save £{cancelled*130:.0f}"
    }

# === ROOT ===
@app.get("/")
async def root():
    return {"message": "GrowthEasy AI Live"}