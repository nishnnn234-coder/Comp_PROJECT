import hashlib
import json
import math
import os
from io import BytesIO
from typing import Dict, Any

from fastapi import FastAPI, File, UploadFile, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic_settings import BaseSettings
from groq import Groq
from pypdf import PdfReader

# =====================================================================
# 1. ENVIRONMENT & CONFIGURATION MANAGEMENT
# =====================================================================
# This manages configuration via environment variables, standard for full-stack.
class Settings(BaseSettings):
    app_name: str = "TrustGuard Guardian Platform"
    environment: str = os.getenv("ENVIRONMENT", "development")
    
    # IMPORTANT: Set GROQ_API_KEY in your environment variables
    # For Streamlit deployment, use st.secrets["GROQ_API_KEY"]
    groq_api_key: str = os.getenv("GROQ_API_KEY", "")
    
    max_file_size_bytes: int = 100 * 1024 * 1024  # 100 MB limit
    entropy_high_risk_threshold: float = 6.8

    class Config:
        env_file = ".env" # Loads from a local .env file if present

settings = Settings()

# =====================================================================
# 2. FASTAPI APP INITIALIZATION
# =====================================================================
app = FastAPI(
    title=settings.app_name,
    version="2.0.0",
)

# Enable CORS (Cross-Origin Resource Sharing)
# Required for frontends running on different origins to call the API.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # In production, restrict this to specific domains
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

# Load the single HTML page to serve as the root
# In production, static files would typically be served via a proxy like Nginx.
STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
if os.path.exists(STATIC_DIR):
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

# =====================================================================
# 3. CORE DOMAIN LOGIC / SERVICES
# =====================================================================
# Decoupled utility functions for file analysis

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

# =====================================================================
# 4. API ROUTES
# =====================================================================

@app.get("/", response_class=HTMLResponse)
async def serve_index():
    """Serves the dashboard directly from root URL."""
    html_path = os.path.join(STATIC_DIR, "index.html")
    if os.path.exists(html_path):
        with open(html_path, "r", encoding="utf-8") as f:
            return f.read()
    return "<h1>TrustGuard API Online</h1><p>Frontend file not found.</p>"

@app.get("/api/health")
async def health_check():
    """Standard API health endpoint."""
    return {
        "status": "healthy",
        "system": settings.app_name,
        "version": "2.0.0"
    }

@app.post("/api/scan")
async def scan_artifact(file: UploadFile = File(...)):
    """Main endpoint for file upload and AI analysis."""
    # 1. API Key Validation
    if not settings.groq_api_key:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Groq API key is not configured on the server."
        )

    # 2. File Processing
    try:
        # Read file contents and enforce size limit
        content = await file.read()
        if len(content) > settings.max_file_size_bytes:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail=f"File exceeds maximum size of {settings.max_file_size_bytes // (1024*1024)} MB."
            )

        # Generate cryptographic SHA-256 hash
        sha256_hash = hashlib.sha256(content).hexdigest()
        
        # Calculate file entropy (indicator of obfuscation)
        entropy = calculate_shannon_entropy(content)
        
        # Determine file extension
        filename = file.filename.lower()
        ext = filename.split(".")[-1] if "." in filename else ""

        # 3. AI Threat Analysis via Groq
        groq_client = Groq(api_key=settings.groq_api_key)
        
        # Heuristic rules to determine risk verdict
        is_executable = ext in ["exe", "dll", "bat", "vbs", "ps1", "sh", "scr"]
        if is_executable or entropy >= settings.entropy_high_risk_threshold:
            verdict = "High Risk"
        elif entropy > 5.2:
            verdict = "Suspicious"
        else:
            verdict = "Verified Clean"

        system_prompt = (
            "You are a professional enterprise Zero-Trust Cybersecurity Analyst. "
            "Examine the provided metadata of an uploaded file. Provide a concise technical threat assessment in 2-3 sentences."
        )

        user_prompt = f"""
        Filename: {file.filename}
        File Size: {len(content)} bytes
        SHA-256 Hash: {sha256_hash}
        Shannon Entropy: {entropy} / 8.0
        Calculated Verdict: {verdict}
        """

        response = groq_client.chat.completions.create(
            model="llama-3.1-8b-instant",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            temperature=0.2
        )
        ai_analysis = response.choices[0].message.content

        # Return standardized JSON response
        return {
            "status": "success",
            "filename": file.filename,
            "size_bytes": len(content),
            "sha256": sha256_hash,
            "entropy": entropy,
            "verdict": verdict,
            "analysis": ai_analysis
        }

    except HTTPException as he:
        raise he
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")
