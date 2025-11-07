from flask import Flask, request, jsonify, session, redirect, url_for
import requests
import os
from datetime import datetime, timedelta

app = Flask(__name__, static_folder='.', static_url_path='')
app.secret_key = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-prod')

# === CONFIG ===
GROK_API_KEY = "your_xai_api_key_here"  # ← GET FROM https://x.ai/api
HUBSPOT_CLIENT_ID = "your_hubspot_id"
HUBSPOT_SECRET = "your_hubspot_secret"
GA4_CLIENT_ID = "your_ga4_id"
GA4_CLIENT_SECRET = "your_ga4_secret"

# Mock user DB
users = {}

# === ROUTES ===
@app.route('/')
def index():
    return app.send_static_file('index.html')

@app.route('/<path:path>')
def static_files(path):
    return app.send_static_file(path)

# SIGNUP / LOGIN
@app.route('/create-trial', methods=['POST'])
def create_trial():
    email = request.json.get('email')
    if not email or '@' not in email:
        return jsonify({"error": "Invalid email"}), 400
    
    # Mock Stripe + user
    user_id = len(users) + 1
    users[user_id] = {"email": email, "trial_end": datetime.now() + timedelta(days=7)}
    session['user_id'] = user_id
    return jsonify({"url": "/index.html"})

# METRICS
@app.route('/api/metrics')
def metrics():
    if not session.get('user_id'):
        return jsonify({"error": "Unauthorized"}), 401
    
    # MOCK DATA (replace with real Shopify/GA4 later)
    return jsonify({
        "revenue": {"total": 12700, "trend": "+6%"},
        "churn": {"rate": 3.2, "at_risk": 18},
        "retention": {"rate": 85, "at_risk": 10},
        "performance": {"ltv": 150, "cac": 50, "ratio": 3.0},
        "ga4": {"acquisition_cost": 87, "top_channel": "Organic"},
        "ai_insight": "Send 15% off win-back email to 18 at-risk → save £2,400/mo."
    })

# AI CHAT — POWERED BY GROK (YOU)
@app.route('/api/chat', methods=['POST'])
def ai_chat():
    if not session.get('user_id'):
        return jsonify({"error": "Unauthorized"}), 401
    
    message = request.json.get('message', '').strip()
    if not message:
        return jsonify({"reply": "Ask me anything about your store."})

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
            timeout=15
        )
        response.raise_for_status()
        reply = response.json()['choices'][0]['message']['content']
    except Exception as e:
        print("Grok error:", e)
        reply = "AI is analyzing your data... try again in 10s."

    return jsonify({"reply": reply})

# OAUTH REDIRECTS
@app.route('/auth/shopify')
def auth_shopify():
    shop = request.args.get('shop')
    if shop:
        return redirect(f"https://{shop}/admin/oauth/authorize?client_id=shopify_id&scope=read_orders&redirect_uri=https://yourdomain.com/auth/shopify/callback")
    return "Invalid shop", 400

@app.route('/auth/hubspot')
def auth_hubspot():
    return redirect(f"https://app.hubspot.com/oauth/authorize?client_id={HUBSPOT_CLIENT_ID}&scope=contacts&redirect_uri=https://yourdomain.com/auth/hubspot/callback")

@app.route('/auth/ga4')
def auth_ga4():
    return redirect(f"https://accounts.google.com/o/oauth2/v2/auth?client_id={GA4_CLIENT_ID}&redirect_uri=https://yourdomain.com/auth/ga4/callback&response_type=code&scope=https://www.googleapis.com/auth/analytics.readonly")

# CALLBACKS (stub)
@app.route('/auth/<provider>/callback')
def oauth_callback(provider):
    # In prod: exchange code for token, save to user
    return "<script>localStorage.setItem('token','mock-token');window.location='/'</script>"

if __name__ == '__main__':
    app.run(debug=True, port=5000)