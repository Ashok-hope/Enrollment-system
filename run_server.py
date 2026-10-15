import uvicorn
import os
import sys

# Ensure UTF-8 output on Windows consoles if supported
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    print("=" * 70)
    print("ZERO-TRUST CRYPTOGRAPHIC COURSE ENROLLMENT & LEDGER SYSTEM")
    print(f"Main Course Portal:         http://127.0.0.1:{port}/")
    print(f"Security & Attack Lab:       http://127.0.0.1:{port}/attacks")
    print(f"Blockchain Ledger Explorer: http://127.0.0.1:{port}/explorer")
    print(f"Interactive API Docs:       http://127.0.0.1:{port}/docs")
    print("-" * 70)
    print("Quick Evaluation Accounts (for multi-tab testing):")
    print("  * Instructor: dr.turing@university.edu / admin123")
    print("  * Student 1:  alice@student.edu        / alice123")
    print("  * Student 2:  bob@student.edu          / bob123")
    print("=" * 70)
    uvicorn.run("backend.app:app", host="0.0.0.0", port=port, reload=True)
