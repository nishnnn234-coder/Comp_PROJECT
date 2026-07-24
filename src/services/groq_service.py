import logging
from groq import Groq

logger = logging.getLogger("trustguard")

def analyze_artifact_with_groq(
    api_key: str,
    filename: str,
    size_bytes: int,
    sha256_hash: str,
    entropy: float,
    verdict: str,
    sample_text: str
) -> str:
    """Queries Groq Llama-3 model for technical security threat summaries."""
    if not api_key:
        logger.error("Groq API key is unconfigured.")
        return "AI analysis offline: GROQ_API_KEY environment variable is missing."

    try:
        client = Groq(api_key=api_key)
        system_prompt = (
            "You are a senior Zero-Trust Security Analyst. "
            "Examine the file metadata and sample content provided. "
            "Provide a concise, 2 to 3 sentence technical threat assessment detailing potential risks."
        )

        user_prompt = f"""
        Filename: {filename}
        Size: {size_bytes} bytes
        SHA-256 Hash: {sha256_hash}
        Shannon Entropy: {entropy} / 8.0
        Calculated Rule Verdict: {verdict}
        Sample Text:
        {sample_text[:1200] if sample_text else 'Binary file (No plain text content extracted).'}
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

    except Exception as e:
        logger.error(f"Groq API call exception: {str(e)}")
        return "AI Heuristic Analysis unavailable. Rule-based evaluation complete."
