import math
import logging

logger = logging.getLogger("trustguard")

MAGIC_BYTES = {
    "pdf": [b"%PDF"],
    "exe": [b"MZ"],
    "zip": [b"PK\x03\x04", b"PK\x05\x06"],
    "png": [b"\x89PNG\r\n\x1a\n"],
    "jpg": [b"\xff\xd8\xff"]
}

def calculate_shannon_entropy(data: bytes) -> float:
    """Calculate Shannon Entropy (0.0 to 8.0) to detect encryption, packing, or obfuscation."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    for x in range(256):
        p_x = data.count(x) / length
        if p_x > 0:
            entropy -= p_x * math.log2(p_x)
    return round(entropy, 2)

def verify_file_signature(data: bytes, filename: str) -> bool:
    """Validates magic bytes against file extension to catch spoofed files."""
    ext = filename.lower().split(".")[-1] if "." in filename else ""
    if ext in MAGIC_BYTES:
        signatures = MAGIC_BYTES[ext]
        matches = any(data.startswith(sig) for sig in signatures)
        if not matches:
            logger.warning(f"Signature mismatch detected for extension .{ext}")
            return False
    return True

def calculate_verdict(filename: str, entropy: float, signature_valid: bool, threshold: float = 6.8) -> str:
    """Evaluates rule-based threat verdict based on extension, entropy, and headers."""
    ext = filename.lower().split(".")[-1] if "." in filename else ""
    is_executable = ext in ["exe", "dll", "bat", "vbs", "ps1", "sh", "scr"]

    if not signature_valid or is_executable or entropy >= threshold:
        return "High Risk"
    elif entropy > 5.2:
        return "Suspicious"
    return "Verified Clean"
