import hashlib
import json
import math
import os
from io import BytesIO
from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from groq import Groq
from pypdf import PdfReader

# Initialize App
app = FastAPI(
    title="TrustGuard Cyber Intelligence API",
    version="2.4.0",
    description="Zero-Trust Threat Telemetry & AI Malware Sandbox Engine"
)

# Enable CORS for cross-origin requests
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Load Configuration JSON
CONFIG_PATH = os.path.join(os.path.dirname(__file__), "..", "config", "app_config.json")
try:
    with open(CONFIG_PATH, "r") as f:
        APP_CONFIG = json.load(f)
except Exception:
    APP_CONFIG = {"security_policy": {"entropy_high_risk_threshold": 6.8}}

# Mount static frontend directory
STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
if os.path.exists(STATIC_DIR):
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


def get_groq_client():
    api_key = os.environ.get("GROQ_API_KEY")
    if not api_key:
        raise HTTPException(
            status_code=500, 
            detail="GROQ_API_KEY environment variable is missing on server."
        )
    return Groq(api_key=api_key)


def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon Entropy (0.0 to 8.0) to detect obfuscation/encryption."""
    if not data:
        return 0.0
    entropy = 0.0
    for x in range(256):
        p_x = data.count(x) / len(data)
        if p_x > 0:
            entropy -= p_x * math.log2(p_x)
    return round(entropy, 2)


@app.get("/", response_class=HTMLResponse)
async def serve_frontend():
    """Serves the dashboard directly from root URL."""
    html_file = os.path.join(STATIC_DIR, "index.html")
    if os.path.exists(html_file):
        with open(html_file, "r", encoding="utf-8") as f:
            return f.read()
    return "<h1>TrustGuard API Online</h1><p>Frontend static file not found.</p>"


@app.get("/api/health")
async def health_check():
    return {"status": "online", "system": "TrustGuard Guardian Engine v2.4"}


@app.post("/api/scan")
async def scan_artifact(file: UploadFile = File(...)):
    try:
        content = await file.read()
        
        # 1. SHA-256 Hash Generation
        sha256_hash = hashlib.sha256(content).hexdigest()
        
        # 2. Entropy Calculation
        entropy = calculate_entropy(content)
        
        # 3. Extract text content (PDF / Text file sample)
        extracted_text = ""
        filename = file.filename.lower()
        
        if filename.endswith(".pdf"):
            try:
                reader = PdfReader(BytesIO(content))
                for page in reader.pages[:5]:  # Read first 5 pages for efficiency
                    text = page.extract_text()
                    if text:
                        extracted_text += text
            except Exception:
                extracted_text = "[PDF Text Extraction Failed]"
        else:
            extracted_text = content[:3000].decode("utf-8", errors="ignore")

        # 4. Groq LLM Threat Analysis Prompt
        client = get_groq_client()
        system_prompt = (
            "You are an enterprise Zero-Trust Cyber Security Analyst. "
            "Analyze the file metadata and text snippet. Provide a concise 2-3 sentence assessment "
            "highlighting potential risks, obfuscation, or policy compliance concerns."
        )

        user_prompt = f"""
        Filename: {file.filename}
        File Size: {len(content)} bytes
        SHA-256 Hash: {sha256_hash}
        Shannon Entropy: {entropy} / 8.0
        
        Extracted Sample:
        {extracted_text[:1500] if extracted_text else 'Binary file (non-text executable).'}
        """

        response = client.chat.completions.create(
            model="llama-3.1-8b-instant",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            temperature=0.2
        )

        ai_analysis = response.choices[0].message.content

        # Determine Risk Verdict
        ext = filename.split(".")[-1] if "." in filename else ""
        is_executable = ext in ["exe", "dll", "bat", "vbs", "ps1", "sh", "scr"]
        high_threshold = APP_CONFIG.get("security_policy", {}).get("entropy_high_risk_threshold", 6.8)

        if is_executable or entropy >= high_threshold:
            verdict = "High Risk"
        elif entropy > 5.2:
            verdict = "Suspicious"
        else:
            verdict = "Verified Clean"

        return {
            "status": "success",
            "filename": file.filename,
            "size_bytes": len(content),
            "sha256": sha256_hash,
            "entropy": entropy,
            "verdict": verdict,
            "analysis": ai_analysis
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")
