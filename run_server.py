import uvicorn
import os

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    print(f"Starting Zero-Trust Cryptographic Ledger System on http://127.0.0.1:{port}")
    uvicorn.run("backend.app:app", host="0.0.0.0", port=port, reload=True)
