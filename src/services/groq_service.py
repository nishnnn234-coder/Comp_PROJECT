import os
from fastapi import HTTPException
from groq import Groq

def get_groq_client() -> Groq:
    api_key = os.environ.get("GROQ_API_KEY")
    if not api_key:
        raise HTTPException(
            status_code=500,
            detail="GROQ_API_KEY environment variable is missing on server."
        )
    return Groq(api_key=api_key)

def analyze_artifact_with_groq(filename: str, size: int, hash_val: str, entropy: float, sample: str) -> str:
    client = get_groq_client()
    system_prompt = (
        "You are an enterprise Zero-Trust Cybersecurity Threat Analyst. "
        "Examine the provided metadata and snippet. Provide a concise 2-3 sentence technical threat assessment."
    )
    user_prompt = f"""
    Filename: {filename}
    Size: {size} bytes
    SHA-256: {hash_val}
    Entropy: {entropy} / 8.0
    
    Sample Data:
    {sample[:1500] if sample else 'Binary artifact (non-text).'}
    """
    
    response = client.chat.completions.create(
        model="llama-3.1-8b-instant",
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ],
        temperature=0.2
    )
    return response.choices[0].message.content
