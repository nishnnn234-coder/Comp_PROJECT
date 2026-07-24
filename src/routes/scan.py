import hashlib
from io import BytesIO
from fastapi import APIRouter, File, UploadFile, HTTPException
from pypdf import PdfReader
from src.services.analyzer import calculate_entropy, derive_verdict
from src.services.groq_service import analyze_artifact_with_groq

router = APIRouter(prefix="/api", tags=["Scanner"])

@router.post("/scan")
async def scan_artifact(file: UploadFile = File(...)):
    try:
        content = await file.read()
        sha256_hash = hashlib.sha256(content).hexdigest()
        entropy = calculate_entropy(content)
        
        extracted_text = ""
        filename = file.filename.lower()
        
        if filename.endswith(".pdf"):
            try:
                reader = PdfReader(BytesIO(content))
                for page in reader.pages[:5]:
                    text = page.extract_text()
                    if text:
                        extracted_text += text
            except Exception:
                extracted_text = "[PDF Extraction Error]"
        else:
            extracted_text = content[:3000].decode("utf-8", errors="ignore")

        ai_analysis = analyze_artifact_with_groq(
            filename=file.filename,
            size=len(content),
            hash_val=sha256_hash,
            entropy=entropy,
            sample=extracted_text
        )

        verdict = derive_verdict(file.filename, entropy, 6.8)

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
        raise HTTPException(status_code=500, detail=str(e))
