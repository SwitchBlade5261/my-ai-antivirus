from fastapi import FastAPI
import pydantic
import requests

app = FastAPI()

# SHA-256 fingerprint of the EICAR test string
BLACK_LISTED_HASHES = [
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
]

class FileCheck(pydantic.BaseModel):
    file_path: str
    file_hash: str

@app.get("/")
def home():
    return {"status": "Dual Threat Engine Online"}

@app.post("/analyze-file")
def analyze_file(data: FileCheck):
    # Check if the file matches our blacklisted threat signatures
    if data.file_hash in BLACK_LISTED_HASHES:
        try:
            # Gather background location info for the forensic report
            geo_req = requests.get("https://ipapi.co", timeout=3).json()
            city = geo_req.get("city", "Unknown City")
            country = geo_req.get("country_name", "Unknown Country")
        except:
            city, country = "Unknown City", "Unknown Country"

        return {
            "status": "BLOCK",
            "reason": "File signature matches a known malicious campaign template.",
            "city": city,
            "country": country
        }
    
    return {"status": "ALLOW"}
