import hashlib
from io import BytesIO
from fastapi import APIRouter, File, UploadFile, HTTPException, status
from pypdf import PdfReader

from src.services.analyzer import calculate_shannon_entropy, verify_file_signature, calculate_verdict
from src.services.groq_service import analyze_artifact_with_groq

router = APIRouter(prefix="/api", tags=["Threat Scanning"])

MAX_FILE_SIZE = 50 * 1024 * 1024  # 50 MB Payload Limit

@router.post("/scan")
async def scan_artifact(file: UploadFile = File(...)):
    # Chunked read to prevent high RAM consumption
    contents = bytearray()
    chunk_size = 1024 * 1024  # 1 MB chunks
    
    while chunk := await file.read(chunk_size):
        contents.extend(chunk)
        if len(contents) > MAX_FILE_SIZE:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail="Payload exceeds maximum allowed limit of 50 MB."
            )

    raw_data = bytes(contents)
    filename = file.filename.lower()

    # 1. Telemetry Computations
    sha256_hash = hashlib.sha256(raw_data).hexdigest()
    entropy = calculate_shannon_entropy(raw_data)
    signature_valid = verify_file_signature(raw_data, filename)
    verdict = calculate_verdict(filename, entropy, signature_valid)

    # 2. Text Content Extraction (if PDF or Text)
    extracted_text = ""
    if filename.endswith(".pdf"):
        try:
            reader = PdfReader(BytesIO(raw_data))
            for page in reader.pages[:5]:
                text = page.extract_text()
                if text:
                    extracted_text += text
        except Exception:
            extracted_text = "[PDF Parsing Fault]"
    else:
        extracted_text = raw_data[:3000].decode("utf-8", errors="ignore")

    # 3. AI Heuristics via Groq
    from src.main import settings
    ai_analysis = analyze_artifact_with_groq(
        api_key=settings.groq_api_key,
        filename=file.filename,
        size_bytes=len(raw_data),
        sha256_hash=sha256_hash,
        entropy=entropy,
        verdict=verdict,
        sample_text=extracted_text
    )

    return {
        "status": "success",
        "filename": file.filename,
        "size_bytes": len(raw_data),
        "sha256": sha256_hash,
        "entropy": entropy,
        "signature_valid": signature_valid,
        "verdict": verdict,
        "analysis": ai_analysis
    }
