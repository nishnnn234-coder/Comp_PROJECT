import hashlib
import json
import logging
import math
import os
from io import BytesIO
from typing import Dict, Any

from fastapi import FastAPI, File, UploadFile, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from pydantic_settings import BaseSettings
from groq import Groq
from pypdf import PdfReader

# =====================================================================
# 1. STRUCTURED LOGGING CONFIGURATION
# =====================================================================
logging.basicConfig(
    level=logging.INFO,
    format='{"time": "%(asctime)s", "level": "%(levelname)s", "module": "%(module)s", "message": "%(message)s"}'
)
logger = logging.getLogger("trustguard")

# =====================================================================
# 2. ENVIRONMENT & CONFIGURATION MANAGEMENT
# =====================================================================
class Settings(BaseSettings):
    app_name: str = "TrustGuard Cyber Platform"
    environment: str = os.getenv("ENVIRONMENT", "production")
    groq_api_key: str = os.getenv("GROQ_API_KEY", "")
    allowed_origins: str = os.getenv("ALLOWED_ORIGINS", "*")
    max_file_size_bytes: int = 10 * 1024 * 1024  # 10 MB limit
    entropy_high_risk_threshold: float = 6.8

    class Config:
        env_file = ".env"

settings = Settings()

# =====================================================================
# 3. FASTAPI APP INITIALIZATION & SECURITY MIDDLEWARE
# =====================================================================
app = FastAPI(
    title=settings.app_name,
    version="3.0.0",
    docs_url="/api/docs" if settings.environment == "development" else None,
    redoc_url=None
)

# CORS Policy
origins = [origin.strip() for origin in settings.allowed_origins.split(",")]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

# Security Headers Middleware
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Content-Security-Policy"] = "default-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com;"
    return response

# =====================================================================
# 4. STATIC FILE MOUNTING
# =====================================================================
STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
if os.path.exists(STATIC_DIR):
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

# =====================================================================
# 5. CORE DOMAIN SERVICES
# =====================================================================
def calculate_shannon_entropy(data: bytes) -> float:
    """Calculates Shannon Entropy (0.0 to 8.0) to detect encryption/packing."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    for x in range(256):
        p_x = data.count(x) / length
        if p_x > 0:
            entropy -= p_x * math.log2(p_x)
    return round(entropy, 2)

def verify_file_header(data: bytes, filename: str) -> bool:
    """Basic magic byte validation for common formats."""
    if filename.endswith(".pdf") and not data.startswith(b"%PDF"):
        return False
    if filename.endswith(".exe") and not data.startswith(b"MZ"):
        return False
    return True

# =====================================================================
# 6. API ROUTES
# =====================================================================
@app.get("/", response_class=HTMLResponse)
async def serve_index():
    html_path = os.path.join(STATIC_DIR, "index.html")
    if os.path.exists(html_path):
        with open(html_path, "r", encoding="utf-8") as f:
            return f.read()
    return "<h1>TrustGuard API Online</h1>"

@app.get("/api/health")
async def health_check():
    return {
        "status": "healthy",
        "environment": settings.environment,
        "groq_configured": bool(settings.groq_api_key)
    }

@app.post("/api/scan")
async def scan_artifact(file: UploadFile = File(...)):
    # 1. API Key Validation
    if not settings.groq_api_key:
        logger.error("GROQ_API_KEY environment variable is missing.")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Server intelligence engine unconfigured."
        )

    # 2. Read Payload & Size Enforcement
    content = await file.read()
    if len(content) > settings.max_file_size_bytes:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"File exceeds maximum allowed size of {settings.max_file_size_bytes // (1024*1024)} MB."
        )

    # 3. Magic Byte Verification
    if not verify_file_header(content, file.filename.lower()):
        logger.warning(f"File signature mismatch detected for {file.filename}")

    # 4. Telemetry Computations
    sha256_hash = hashlib.sha256(content).hexdigest()
    entropy = calculate_shannon_entropy(content)
    
    extracted_text = ""
    filename = file.filename.lower()

    if filename.endswith(".pdf"):
        try:
            reader = PdfReader(BytesIO(content))
            for page in reader.pages[:5]:
                text = page.extract_text()
                if text:
                    extracted_text += text
        except Exception as e:
            logger.warning(f"Failed PDF extraction for {file.filename}: {str(e)}")
            extracted_text = "[PDF Extraction Fault]"
    else:
        extracted_text = content[:3000].decode("utf-8", errors="ignore")

    # 5. Groq LLM Inference
    try:
        groq_client = Groq(api_key=settings.groq_api_key)
        response = groq_client.chat.completions.create(
            model="llama-3.1-8b-instant",
            messages=[
                {
                    "role": "system",
                    "content": "You are a senior SOC analyst. Provide a brief 2-sentence threat assessment of the file."
                },
                {
                    "role": "user",
                    "content": f"File: {file.filename}\nHash: {sha256_hash}\nEntropy: {entropy}\nSample: {extracted_text[:1000]}"
                }
            ],
            temperature=0.2
        )
        ai_analysis = response.choices[0].message.content
    except Exception as e:
        logger.error(f"Groq API call failed: {str(e)}")
        ai_analysis = "AI Heuristic Analysis unavailable. Rule-based evaluation complete."

    # 6. Risk Verdict Logic
    ext = filename.split(".")[-1] if "." in filename else ""
    is_executable = ext in ["exe", "dll", "bat", "vbs", "ps1", "sh", "scr"]
    
    if is_executable or entropy >= settings.entropy_high_risk_threshold:
        verdict = "High Risk"
    elif entropy > 5.2:
        verdict = "Suspicious"
    else:
        verdict = "Verified Clean"

    logger.info(f"Scanned {file.filename} | Verdict: {verdict} | Entropy: {entropy}")

    return {
        "status": "success",
        "filename": file.filename,
        "size_bytes": len(content),
        "sha256": sha256_hash,
        "entropy": entropy,
        "verdict": verdict,
        "analysis": ai_analysis
    }
