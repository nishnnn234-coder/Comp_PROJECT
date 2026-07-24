# TrustGuard Enterprise Cyber Intelligence Platform

An AI-driven threat sandbox and zero-trust telemetry application powered by FastAPI and Groq LLM (`llama-3.1-8b-instant`).

## Features
- **SHA-256 Cryptographic Hashing**: Real-time hash calculation.
- **Shannon Entropy Scoring**: Detects obfuscated or encrypted binary payloads.
- **Groq LLM Integration**: Generates zero-trust security reports on uploaded files.
- **Unified Single-Server Architecture**: FastAPI serves both API routes and static frontend interface.

## Local Running
```bash
pip install -r requirements.txt
export GROQ_API_KEY="your_groq_api_key_here"
uvicorn src.main:app --reload --port 8000
