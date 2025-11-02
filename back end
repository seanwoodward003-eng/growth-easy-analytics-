# growth-easy-analytics-
data analytics mvp code 
[main.py](https://github.com/user-attachments/files/23292012/main.py)
from dotenv import load_dotenv

import os



# Load .env

load_dotenv()



# DEBUG

print("API_KEY:", os.getenv("API_KEY"))

print("OPENAI KEY:", os.getenv("OPENAI_API_KEY"))



from fastapi import FastAPI, Header, HTTPException

from fastapi.responses import JSONResponse

import json

from datetime import datetime

import snowflake.connector

from openai import OpenAI



# === ALL KEYS FROM .env (SAFE) ===

API_KEY = os.getenv('API_KEY')

SNOWFLAKE_USER = os.getenv('SNOWFLAKE_USER')

SNOWFLAKE_PASSWORD = os.getenv('SNOWFLAKE_PASSWORD')

SNOWFLAKE_ACCOUNT = os.getenv('SNOWFLAKE_ACCOUNT')

SNOWFLAKE_WAREHOUSE = os.getenv('SNOWFLAKE_WAREHOUSE')

SNOWFLAKE_DATABASE = os.getenv('SNOWFLAKE_DATABASE')

SNOWFLAKE_SCHEMA = os.getenv('SNOWFLAKE_SCHEMA')



# === OPENAI: HARD-CODED (TEMP FIX) ===

openai_client = OpenAI(api_key="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")



app = FastAPI()


from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
CORSMiddleware,
allow_origins=["*"], # Dev mode
allow_credentials=True,
allow_methods=["*"],
allow_headers=["*"],
)



# === VERIFY API KEY ===

def verify_api_key(api_key: str):

    if api_key != API_KEY:

        raise HTTPException(status_code=401, detail="Invalid API Key")



# === SNOWFLAKE CONNECTION ===

def get_snowflake_conn():

    return snowflake.connector.connect(

        user=SNOWFLAKE_USER,

        password=SNOWFLAKE_PASSWORD,

        account=SNOWFLAKE_ACCOUNT,

        warehouse=SNOWFLAKE_WAREHOUSE,

        database=SNOWFLAKE_DATABASE,

        schema=SNOWFLAKE_SCHEMA

    )



# === MOCK DATA FUNCTIONS ===

def fetch_shopify_orders(api_key, password, shop):

    return {"orders": [{"customer_id": 1, "status": "cancelled"}, {"customer_id": 2, "status": "active"}]}



def fetch_hubspot_contacts():

    return {"contacts": [{"id": 1, "status": "inactive"}, {"id": 2, "status": "active"}]}



def get_ga4_acquisition():

    return {"acquisition_cost": 45.0, "top_channel": "Email (40%)"}



def get_retention():

    return {"retention_rate": 85.0, "at_risk": 10}



def get_performance():

    return {"ltv": 150.0, "cac": 50.0, "margin": 30.0}



def get_revenue():

    return {"total": 12700.0, "trend": "+6%", "breakdown": "60% recurring, 40% one-time"}



# === CHURN CALCULATIONS ===

def calculate_shopify_churn(orders):

    cancelled = len([o for o in orders["orders"] if o["status"] == "cancelled"])

    total = len(orders["orders"])

    return {"churn_rate": (cancelled / total * 100) if total > 0 else 0, "at_risk_customers": cancelled}



def calculate_hubspot_churn(contacts):

    inactive = len([c for c in contacts["contacts"] if c["status"] == "inactive"])

    total = len(contacts["contacts"])

    return {"churn_rate": (inactive / total * 100) if total > 0 else 0, "at_risk": inactive}



# === STORE IN SNOWFLAKE ===

def store_in_snowflake(data):

    try:

        conn = get_snowflake_conn()

        cur = conn.cursor()

        cur.execute("""

            INSERT INTO analytics_metrics (

                timestamp, shopify_churn_rate, shopify_at_risk, hubspot_churn_rate, hubspot_at_risk,

                ga4_abandon_rate, ga4_acquisition_cost, ga4_top_channel, retention_rate, retention_at_risk,

                ltv, cac, margin, revenue_total, revenue_trend, revenue_breakdown

            ) VALUES (

                %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s

            )

        """, (

            data.get("timestamp"),

            data["shopify"].get("churn_rate"),

            data["shopify"].get("at_risk_customers"),

            data.get("hubspot", {}).get("churn_rate"),

            data.get("hubspot", {}).get("at_risk"),

            0.0,

            data["ga4"].get("acquisition_cost"),

            data["ga4"].get("top_channel"),

            data["retention"].get("retention_rate"),

            data["retention"].get("at_risk"),

            data["performance"].get("ltv"),

            data["performance"].get("cac"),

            data["performance"].get("margin"),

            data["revenue"].get("total"),

            data["revenue"].get("trend"),

            data["revenue"].get("breakdown")

        ))

        conn.commit()

        cur.close()

        conn.close()

        return True

    except Exception as e:

        print(f"Snowflake error: {e}")

        return False



# === FETCH DATA (MOCK) ===

async def fetchData(endpoint):

    if endpoint == "shopify/churn":

        return calculate_shopify_churn(fetch_shopify_orders(

            os.getenv('SHOPIFY_API_KEY'), os.getenv('SHOPIFY_PASSWORD'), os.getenv('SHOPIFY_SHOP')

        ))

    elif endpoint == "hubspot/churn":

        return calculate_hubspot_churn(fetch_hubspot_contacts())

    elif endpoint == "ga4/acquisition":

        return get_ga4_acquisition()

    elif endpoint == "retention":

        return get_retention()

    elif endpoint == "performance":

        return get_performance()

    elif endpoint == "revenue":

        return get_revenue()

    return {"error": "Endpoint not found"}



# === AI INSIGHTS ===

@app.get("/ai/insights", response_class=JSONResponse)

async def get_ai_insights(

    api_key: str = Header(..., alias="X-API-Key"),  # ← FIX: MAPS X-API-Key TO api_key

    endpoint: str = Header(...),

    user_id: str = Header(default="unknown_user", alias="user-id")  # ← OPTIONAL + alias

):

    verify_api_key(api_key)

    data = await fetchData(endpoint)

    if data.get("error"):

        return JSONResponse(status_code=500, content={"error": "No data for AI analysis"})

    

    prompt = f"Analyze this business data for user {user_id} and give actionable, personalized insights: {json.dumps(data)}. Focus on churn, acquisition, revenue, and recommendations for SMBs."

    

    try:

        response = openai_client.chat.completions.create(

            model="gpt-4o-mini",

            messages=[

                {"role": "system", "content": "You are a helpful AI analyst for SMB growth."},

                {"role": "user", "content": prompt}

            ],

            max_tokens=150

        )

        insight = response.choices[0].message.content

        return JSONResponse(status_code=200, content={"insight": insight, "data": data})

    except Exception as e:

        return JSONResponse(status_code=500, content={"error": str(e)})



# === ENDPOINTS ===

@app.get("/shopify/churn", response_class=JSONResponse)

async def get_shopify_churn(

    api_key: str = Header(...),

    shopify_api_key: str = Header(...),

    shopify_password: str = Header(...),

    shopify_shop: str = Header(...)

):

    verify_api_key(api_key)

    churn = calculate_shopify_churn(fetch_shopify_orders(shopify_api_key, shopify_password, shopify_shop))

    if store_in_snowflake({"shopify": churn, "timestamp": datetime.now().isoformat()}):

        churn["message"] = "Churn fetched and stored successfully."

    return JSONResponse(status_code=200, content=churn)



@app.get("/hubspot/churn", response_class=JSONResponse)

async def get_hubspot_churn(api_key: str = Header(...)):

    verify_api_key(api_key)

    churn = calculate_hubspot_churn(fetch_hubspot_contacts())

    if store_in_snowflake({"hubspot": churn, "timestamp": datetime.now().isoformat()}):

        churn["message"] = "Churn fetched and stored successfully."

    return JSONResponse(status_code=200, content=churn)



@app.get("/ga4/acquisition", response_class=JSONResponse)

async def get_ga4_acquisition_endpoint(api_key: str = Header(...)):

    verify_api_key(api_key)

    acquisition = get_ga4_acquisition()

    if store_in_snowflake({"ga4": acquisition, "timestamp": datetime.now().isoformat()}):

        acquisition["message"] = "Acquisition fetched and stored successfully."

    return JSONResponse(status_code=200, content=acquisition)



@app.get("/retention", response_class=JSONResponse)

async def get_retention_endpoint(api_key: str = Header(...)):

    verify_api_key(api_key)

    retention = get_retention()

    if store_in_snowflake({"retention": retention, "timestamp": datetime.now().isoformat()}):

        retention["message"] = "Retention fetched and stored successfully."

    return JSONResponse(status_code=200, content=retention)



@app.get("/performance", response_class=JSONResponse)

async def get_performance_endpoint(api_key: str = Header(...)):

    verify_api_key(api_key)

    performance = get_performance()

    if store_in_snowflake({"performance": performance, "timestamp": datetime.now().isoformat()}):

        performance["message"] = "Performance fetched and stored successfully."

    return JSONResponse(status_code=200, content=performance)



@app.get("/revenue", response_class=JSONResponse)

async def get_revenue_endpoint(api_key: str = Header(...)):

    verify_api_key(api_key)

    revenue = get_revenue()

    if store_in_snowflake({"revenue": revenue, "timestamp": datetime.now().isoformat()}):

        revenue["message"] = "Revenue fetched and stored successfully."

    return JSONResponse(status_code=200, content=revenue)



@app.get("/metrics", response_class=JSONResponse)

async def get_metrics(

    api_key: str = Header(...),

    shopify_api_key: str = Header(...),

    shopify_password: str = Header(...),

    shopify_shop: str = Header(...)

):

    verify_api_key(api_key)

    

    shopify_churn = calculate_shopify_churn(fetch_shopify_orders(shopify_api_key, shopify_password, shopify_shop))

    hubspot_churn = calculate_hubspot_churn(fetch_hubspot_contacts())

    ga4_acquisition = get_ga4_acquisition()

    retention = get_retention()

    performance = get_performance()

    revenue = get_revenue()



    metrics = {

        "shopify": shopify_churn,

        "hubspot": hubspot_churn,

        "ga4": ga4_acquisition,

        "retention": retention,

        "performance": performance,

        "revenue": revenue,

        "timestamp": datetime.now().isoformat()

    }



    if store_in_snowflake(metrics):

        metrics["message"] = "Metrics fetched and stored successfully."

    else:

        metrics["message"] = "Metrics fetched, but storage failed."



    # Add AI insight

    ai_data = await get_ai_insights(api_key, 'metrics', user_id="user123")

    if not ai_data.get("error"):

        metrics["ai_insight"] = ai_data.get("insight")



    return JSONResponse(status_code=200, content=metrics)



# === RUN SERVER ===

if __name__ == "__main__":

    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)

