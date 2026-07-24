import random
from fastapi import APIRouter

router = APIRouter(prefix="/api", tags=["Telemetry"])

@router.get("/telemetry/stream")
async def get_telemetry():
    events = [
        {"type": "ransomware", "title": "Ransomware Behavioral Execution Prevented", "node": "DESKTOP-FINANCE-04", "status": "Isolated", "level": "danger"},
        {"type": "ato", "title": "Anomalous Geolocation Login Attempt", "node": "185.220.101.5", "status": "MFA Enforced", "level": "warning"},
        {"type": "integrity", "title": "Endpoint Integrity Scan Complete", "node": "2,847 Nodes Active", "status": "Verified", "level": "success"}
    ]
    return {
        "active_threats_blocked": random.randint(2800, 3100),
        "compliance_score": 94.8,
        "recent_event": random.choice(events)
    }
