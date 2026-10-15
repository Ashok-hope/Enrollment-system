# Zero-Trust Cryptographic Course Enrollment & Blockchain Ledger System

An end-to-end cryptographic web application and blockchain ledger that guarantees **Zero-Trust Non-Repudiation, Untrusted Database/Developer Tamper-Resistance, and Confidentiality** for academic course enrollment.

Developed for academic demonstration and evaluation in **Cryptography & Computer Security**.

---

## 🔐 Core Cryptographic Primitives

| Component | Cryptographic Primitive | Implementation Details |
| :--- | :--- | :--- |
| **Identity & Asymmetric Keys** | **ECDSA (secp256r1) / Ed25519** | Client-side generation using Web Crypto API (`window.crypto.subtle`). Private keys stay strictly in the user's browser memory. |
| **Digital Signatures** | **ECDSA with SHA-256 (IEEE P1363 raw r\|\|s)** | Enforces unforgeability under chosen-message attacks (EUF-CMA). |
| **Data Integrity & Chaining** | **SHA-256 Hash Chaining** | Block headers link via $H(\text{index} \parallel \text{prev\_hash} \parallel \text{merkle\_root} \parallel \text{timestamp} \parallel \text{nonce})$. |
| **Inclusion Verification** | **Binary Merkle Tree** | Computes $O(\log N)$ Merkle audit paths to verify transaction inclusion without scanning the full block. |
| **Confidentiality** | **AES-256-GCM** | Authenticated symmetric payload encryption with random 96-bit IV and 128-bit authentication tag. |
| **Invitation Capability Certificates** | **Admin Digital Signature** | $\text{Cert} = \text{Sign}_{\text{AdminPrivKey}}(H(\text{CourseUUID} \parallel \text{StudentPubKey} \parallel \text{Schedule} \parallel \text{Nonce}))$. |
| **Anti-Replay Mechanism** | **Monotonic Cryptographic Nonces** | Prevents transaction replay across courses or semesters. |
| **Time-Lock Window** | **UTC Schedule Bounds** | $\text{ValidFrom} \le T_{\text{submission}} \le \text{ValidUntil}$. |

---

## 🛡️ Threat Model & Cryptographic Defenses

### 1. The Rogue Developer / Compromised Database Attack
- **Threat**: A developer with `root` SQLite/PostgreSQL access attempts to:
  1. Add a fake student into the database `invitations` table.
  2. Alter an existing student's course, grade, or identity details in a block.
  3. Inject an unauthorized enrollee directly into a block.
- **Cryptographic Defense**:
  - The database is treated as an **untrusted medium**.
  - Without the Instructor's private key, forged invitations fail $\text{Verify}_{\text{AdminPubKey}}(\text{Cert})$.
  - Tampering with any byte changes the transaction hash $\to$ breaks the Merkle root $\to$ invalidates the block hash $\to$ cascades through all subsequent block pointers.

### 2. The Instructor Front-Running / Early Enrollment Attack
- **Threat**: The instructor or an insider tries to pre-enroll preferred students before the official enrollment window opens.
- **Cryptographic Defense**:
  - Transaction verification strictly checks that $T_{\text{tx}} \ge \text{ScheduleStartTime}$. Transactions submitted prematurely fail the cryptographic time-lock verification.

### 3. Identity Impersonation / Forgery
- **Threat**: An adversary attempts to enroll on behalf of another student.
- **Cryptographic Defense**:
  - Requires the student's digital signature signed with their private key. Computationally infeasible without the private key.

### 4. Replay Attack
- **Threat**: An eavesdropper intercepts Alice's valid enrollment transaction and re-submits it.
- **Cryptographic Defense**:
  - Cryptographic nonces and student-course bindings ensure each nonce is spent only once. Re-transmissions are rejected immediately.

---

## 🧪 Interactive Security & Attack Simulation Lab

The application includes an **Academic Simulation Sandbox** with 6 one-click attack scenarios:

1. **Simulate Developer DB-Injection (Validated Student)**:
   - Developer injects a student into the DB with a forged signature.
   - *Result*: Caught and flagged as `CRYPTOGRAPHIC FORGERY: Invalid Admin Digital Signature`.
2. **Simulate Developer Block-Injection (Unauthorized Enrollee)**:
   - Developer inserts an enrollee directly into Block #1.
   - *Result*: Caught as `MERKLE ROOT MISMATCH` and `UNAUTHORIZED INJECTION`.
3. **Simulate Storage Record Tampering**:
   - Developer modifies Alice's grade/enrollment payload in Block #1.
   - *Result*: Invalidation of student signature and broken downstream block pointers.
4. **Simulate Early Front-Running Attack**:
   - Early submission to course `CS-902`.
   - *Result*: Rejected by `TIME-LOCK VIOLATION`.
5. **Simulate Replay Attack**:
   - Resubmitting a spent nonce.
   - *Result*: Rejected by `REPLAY ATTACK DETECTED`.
6. **Simulate Block Hash Corruption**:
   - Corrupting block header hash directly in storage.
   - *Result*: Triggers `HASH_CHAIN_BROKEN` at downstream blocks.

---

## 🚀 Quickstart Guide (Local Execution)

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Run Test Suite
```bash
python -m pytest tests
```

### 3. Start the Server
```bash
python run_server.py
```
Open your browser at: **[http://127.0.0.1:8000](http://127.0.0.1:8000)**

---

## 🌐 Hosting & Deployment Instructions

This repository is pre-configured for zero-friction cloud deployment:

### Option A: Render (Recommended Free Hosting)
1. Push this repository to GitHub.
2. Sign in to [Render.com](https://render.com) and click **New Web Service**.
3. Connect your repository.
4. Set:
   - **Environment**: `Python`
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `uvicorn backend.app:app --host 0.0.0.0 --port $PORT`
5. Click **Deploy**.

### Option B: Railway / Fly.io / Docker
Simply deploy using the included `Dockerfile`:
```bash
docker build -t crypto-ledger .
docker run -p 8000:8000 crypto-ledger
```
