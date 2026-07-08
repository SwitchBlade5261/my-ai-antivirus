from fastapi import FastAPI
import pydantic
import requests

app = FastAPI()

# Example list of known malicious IPs
KNOWN_BAD_IPS = ["185.220.101.5"] 

class NetworkAlert(pydantic.BaseModel):
    process_name: str
    remote_ip: str

@app.get("/")
def home():
    return {"status": "Cloud Brain is Online"}

@app.post("/analyze")
def analyze_traffic(alert: NetworkAlert):
    # If it matches a known bad IP, order a block
    if alert.remote_ip in KNOWN_BAD_IPS:
        return {"status": "BLOCK", "reason": "Known malicious server flagged by AI logic."}

    # Pull live threat intelligence data about where the IP is hosted
    try:
        geo_data = requests.get(f"https://ipapi.co{alert.remote_ip}/json/", timeout=3).json()
        isp = geo_data.get("org", "Unknown ISP")
        country = geo_data.get("country_name", "Unknown Country")
    except:
        isp, country = "Unknown ISP", "Unknown Country"

    return {"status": "ALLOW", "isp": isp, "country": country}
