# SecurePay — Tamper-Proof Transaction Signing System

## Stack
- **Python 3.11+** · Flask · cryptography (PyCA) · bcrypt · SQLite

## Setup (2 commands)

```bash
pip install flask cryptography bcrypt
python app.py
```

Open http://localhost:5000

---

## Project structure

```
fintech/
├── crypto.py      # ECDSA key generation, signing, verification
├── database.py    # SQLite schema + all DB helpers
├── app.py         # Flask API (5 endpoints)
├── index.html     # Payment simulation dashboard
└── fintech.db     # Auto-created on first run
```

---

## API

| Method | Endpoint | Purpose |
|--------|----------|---------|
| POST | /keys/generate | Create user + ECDSA keypair |
| POST | /transactions/sign | Sign a payload (returns envelope) |
| POST | /transactions/submit | Verify + commit |
| GET | /transactions | List recent transactions |
| GET | /transactions/<id>/audit | Audit trail for one txn |
| GET | /audit | Full audit log |
| GET | /users | List all users |

---

## Why SHA-256, not bcrypt, for signing

| Role | Algorithm | Why |
|------|-----------|-----|
| Payload digest (ECDSA input) | SHA-256 | Deterministic — same payload = same hash. Required. |
| Password storage | bcrypt | Slow + salted — brute force resistant. |
| Private key encryption | AES-256 (via cryptography BestAvailableEncryption) | Symmetric encryption of the PEM blob. |

bcrypt produces a different output every call (random salt) — if used as the
signing digest, signature verification would always fail.

---

## Demo flows

**Happy path** — Tab 2: enter sender/password/receiver/amount → Sign & submit → watch all 5 pipeline steps go green.

**Tamper test** — Tab 3: load last envelope → click "Tamper: double the amount" → Submit → server detects SHA-256 mismatch → rejected.

**Replay attack** — Tab 4: load the same accepted envelope → Resubmit → server detects duplicate nonce → rejected.

**Audit log** — Tab 5: every event (SIGNED, VERIFIED, REJECTED_TAMPER, REJECTED_REPLAY) logged with timestamp.
