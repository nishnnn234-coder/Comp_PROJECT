import os
import math
import hashlib
import logging
from io import BytesIO
from typing import Dict, Any

from fastapi import FastAPI, File, UploadFile, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic_settings import BaseSettings
from groq import Groq
from pypdf import PdfReader
import pandas as pd

# =====================================================================
# 1. LOGGING & CONFIGURATION
# =====================================================================
logging.basicConfig(
    level=logging.INFO,
    format='{"time": "%(asctime)s", "level": "%(levelname)s", "module": "%(module)s", "message": "%(message)s"}'
)
logger = logging.getLogger("zerotrustone")

class Settings(BaseSettings):
    app_name: str = "Zero TrustOne Platform"
    groq_api_key: str = os.getenv("GROQ_API_KEY", "")
    allowed_origins: str = os.getenv("ALLOWED_ORIGINS", "*")
    max_file_size_bytes: int = 10 * 1024 * 1024  # 10 MB Limit

    class Config:
        env_file = ".env"

settings = Settings()

# =====================================================================
# 2. FASTAPI APP & SECURITY MIDDLEWARE
# =====================================================================
app = FastAPI(title=settings.app_name, version="3.0.0")

# Enable CORS for Frontend Communication
origins = [origin.strip() for origin in settings.allowed_origins.split(",")]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

# Apply Security Headers
@app.middleware("http")
async def apply_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    return response

# =====================================================================
# 3. HELPER FUNCTIONS & AI INFERENCE
# =====================================================================
def calculate_shannon_entropy(data: bytes) -> float:
    """Calculate Shannon Entropy (0.0 to 8.0) for file structure insights."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    for x in range(256):
        p_x = data.count(x) / length
        if p_x > 0:
            entropy -= p_x * math.log2(p_x)
    return round(entropy, 2)

def run_groq_resume_analysis(text: str) -> str:
    """Queries Groq Llama 3.1 8B Instant model with the extracted PDF resume text."""
    if not settings.groq_api_key:
        logger.error("GROQ_API_KEY environment variable missing.")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Groq API key is not configured on the server."
        )

    prompt = f"""
    Analyze this resume and provide:

    1. Professional Summary
    2. Key Skills
    3. Strengths
    4. Weaknesses
    5. Suggested Job Roles
    6. ATS Score out of 100

    Resume Content:
    {text}

    Keep the response professional and concise.
    """

    try:
        client = Groq(api_key=settings.groq_api_key)
        response = client.chat.completions.create(
            model="llama-3.1-8b-instant",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.2
        )
        return response.choices[0].message.content
    except Exception as e:
        logger.error(f"Groq API failure: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"AI model inference failed: {str(e)}"
        )

# =====================================================================
# 4. API ROUTES
# =====================================================================
@app.post("/api/scan")
async def scan_document(file: UploadFile = File(...)):
    """Receives PDF file uploads, processes text & metrics, and returns structured AI results."""
    
    filename = file.filename.lower()
    
    # 1. Size & Extension Enforcement
    content = await file.read()
    if len(content) > settings.max_file_size_bytes:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"File size exceeds the allowed limit of {settings.max_file_size_bytes // (1024*1024)} MB."
        )

    # 2. Extract Text from PDF
    extracted_text = ""
    if filename.endswith(".pdf"):
        try:
            reader = PdfReader(BytesIO(content))
            for page in reader.pages:
                page_text = page.extract_text()
                if page_text:
                    extracted_text += page_text + "\n"
        except Exception as e:
            logger.error(f"Error parsing PDF: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Unable to parse PDF file structure."
            )
    else:
        # Fallback text decoding for non-PDF plain text files
        extracted_text = content.decode("utf-8", errors="ignore")

    if not extracted_text.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No readable text found inside the uploaded document."
        )

    # 3. Compute Metrics (SHA-256, Entropy, Pandas Table Data)
    sha256_hash = hashlib.sha256(content).hexdigest()
    entropy = calculate_shannon_entropy(content)

    overview_df = pd.DataFrame({
        "Feature": ["Resume Uploaded", "Characters Extracted", "AI Model Used", "SHA-256 Hash", "Entropy"],
        "Value": ["Yes", len(extracted_text), "llama-3.1-8b-instant", sha256_hash[:16] + "...", f"{entropy}/8.0"]
    })

    # 4. Run Groq LLM Inference
    ai_result = run_groq_resume_analysis(extracted_text)

    # 5. Return Full Payload
    return {
        "status": "success",
        "filename": file.filename,
        "sha256": sha256_hash,
        "entropy": entropy,
        "analysis": ai_result,
        "overview": overview_df.to_dict(orient="records")
    }

@app.get("/api/health")
async def health_check():
    return {
        "status": "healthy",
        "service": settings.app_name,
        "groq_configured": bool(settings.groq_api_key)
    }

# =====================================================================
# 5. FRONTEND STATIC FILE SERVING
# =====================================================================
STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
if os.path.exists(STATIC_DIR):
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

@app.get("/", response_class=HTMLResponse)
async def serve_index():
    html_path = os.path.join(STATIC_DIR, "index.html")
    if os.path.exists(html_path):
        with open(html_path, "r", encoding="utf-8") as f:
            return f.read()
    return "<h1>Zero TrustOne Backend API Online</h1>"
