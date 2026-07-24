import math

def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon Entropy (0.0 to 8.0) to detect obfuscation/encryption."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    for x in range(256):
        p_x = data.count(x) / length
        if p_x > 0:
            entropy -= p_x * math.log2(p_x)
    return round(entropy, 2)

def derive_verdict(filename: str, entropy: float, high_threshold: float) -> str:
    ext = filename.lower().split(".")[-1] if "." in filename else ""
    is_executable = ext in ["exe", "dll", "bat", "vbs", "ps1", "sh", "scr"]
    
    if is_executable or entropy >= high_threshold:
        return "High Risk"
    elif entropy > 5.2:
        return "Suspicious"
    return "Verified Clean"
