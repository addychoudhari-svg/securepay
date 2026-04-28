"""
app.py — Flask API for the transaction signing and verification system.

Endpoints:
    POST /keys/generate              — create user + ECDSA keypair
    POST /transactions/sign          — sign a transaction payload (returns signature)
    POST /transactions/submit        — verify + commit a signed transaction
    GET  /transactions               — list recent transactions
    GET  /transactions/<id>/audit    — audit trail for one transaction
    GET  /audit                      — full audit log
    GET  /users                      — list users (for demo UI)
"""

import time
import uuid
import json
from datetime import datetime, timezone

from flask import Flask, request, jsonify
from flask import send_from_directory
from cryptography.exceptions import InvalidSignature

from crypto import generate_keypair, sign_transaction, verify_transaction, verify_password
from database import (
    init_db, save_user, get_user, get_public_key,
    get_encrypted_private_key, get_bcrypt_hash,
    nonce_exists, save_nonce,
    save_transaction, get_transactions,
    audit, get_audit_log, list_users
)

app = Flask(__name__, static_folder=".")

# How far in the past or future a transaction timestamp can be (seconds)
REPLAY_WINDOW_SECONDS = 300  # 5 minutes

init_db()


# ── CORS helper ───────────────────────────────────────────────────────────────

@app.after_request
def add_cors(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type"
    response.headers["Access-Control-Allow-Methods"] = "GET,POST,OPTIONS"
    return response

@app.route("/<path:path>", methods=["OPTIONS"])
def options_handler(path):
    return jsonify({}), 200


# ── Serve frontend ────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return send_from_directory(".", "index.html")


# ── Key generation ────────────────────────────────────────────────────────────

@app.route("/keys/generate", methods=["POST"])
def generate_keys():
    """
    Body: { "user_id": "alice", "password": "secret123" }

    Creates an ECDSA P-256 keypair.
    - Private key is AES-256 encrypted with the password, stored in DB.
    - Password is bcrypt-hashed and stored for future auth checks.
    - Public key is stored in plaintext (safe to share).
    """
    body = request.json or {}
    user_id = body.get("user_id", "").strip()
    password = body.get("password", "").strip()

    if not user_id or not password:
        return jsonify(error="user_id and password are required"), 400

    if get_user(user_id):
        return jsonify(error=f"User '{user_id}' already exists"), 409

    encrypted_pem, public_pem, bcrypt_hash = generate_keypair(password)
    save_user(user_id, public_pem, encrypted_pem, bcrypt_hash)

    return jsonify(
        user_id=user_id,
        public_key=public_pem.decode(),
        message="Keypair generated. Private key is encrypted and stored securely."
    ), 201


# ── Transaction signing ───────────────────────────────────────────────────────

@app.route("/transactions/sign", methods=["POST"])
def sign():
    """
    Body: {
        "user_id": "alice",
        "password": "secret123",
        "receiver": "bob",
        "amount": 150.00,
        "currency": "USD"
    }

    Builds a transaction payload (adding txn_id, timestamp, nonce),
    signs it with the user's private key, and returns the envelope.
    The client then submits this envelope to /transactions/submit.
    """
    body = request.json or {}
    user_id  = body.get("user_id", "").strip()
    password = body.get("password", "").strip()
    receiver = body.get("receiver", "").strip()
    amount   = body.get("amount")
    currency = body.get("currency", "USD").strip()

    if not all([user_id, password, receiver, amount]):
        return jsonify(error="user_id, password, receiver, amount are required"), 400

    # Auth check via bcrypt
    stored_hash = get_bcrypt_hash(user_id)
    if not stored_hash or not verify_password(password, stored_hash):
        return jsonify(error="Invalid credentials"), 401

    encrypted_pem = get_encrypted_private_key(user_id)
    if not encrypted_pem:
        return jsonify(error="Private key not found"), 404

    # Build canonical payload
    payload = {
        "txn_id":    str(uuid.uuid4()),
        "sender":    user_id,
        "receiver":  receiver,
        "amount":    float(amount),
        "currency":  currency,
        "timestamp": str(time.time()),
        "nonce":     uuid.uuid4().hex,
    }

    signature = sign_transaction(payload, encrypted_pem, password)
    audit(payload["txn_id"], "SIGNED", f"Signed by {user_id}")

    return jsonify(payload=payload, signature=signature), 200


# ── Transaction submission ────────────────────────────────────────────────────

@app.route("/transactions/submit", methods=["POST"])
def submit():
    """
    Body: { "payload": { ...txn fields... }, "signature": "hex..." }

    5-step verification pipeline:
        1. Field presence check
        2. Timestamp window check  (rejects expired or future transactions)
        3. Nonce uniqueness check  (rejects replays)
        4. ECDSA signature verify  (rejects tampered payloads)
        5. Commit to DB + audit log
    """
    body    = request.json or {}
    payload = body.get("payload")
    sig     = body.get("signature", "")

    # Step 1 — field presence
    if not payload or not sig:
        return jsonify(error="payload and signature are required"), 400

    required_fields = {"txn_id", "sender", "receiver", "amount", "timestamp", "nonce"}
    missing = required_fields - set(payload.keys())
    if missing:
        return jsonify(error=f"Missing fields: {missing}"), 400

    txn_id = payload["txn_id"]

    # Step 2 — timestamp window
    try:
        txn_time = float(payload["timestamp"])
    except (ValueError, TypeError):
        audit(txn_id, "REJECTED_TAMPER", "Invalid timestamp format")
        return jsonify(error="Invalid timestamp"), 400

    age = abs(time.time() - txn_time)
    if age > REPLAY_WINDOW_SECONDS:
        audit(txn_id, "REJECTED_REPLAY", f"Timestamp {age:.0f}s outside window")
        return jsonify(error="Transaction timestamp expired or too far in future"), 400

    # Step 3 — nonce uniqueness (replay prevention)
    if nonce_exists(payload["nonce"]):
        audit(txn_id, "REJECTED_REPLAY", "Nonce already used")
        return jsonify(error="Replay attack detected — nonce already used"), 400

    # Step 4 — ECDSA signature verification
    public_pem = get_public_key(payload["sender"])
    if not public_pem:
        audit(txn_id, "REJECTED_TAMPER", f"Unknown sender: {payload['sender']}")
        return jsonify(error=f"Sender '{payload['sender']}' not found"), 404

    try:
        verify_transaction(payload, sig, public_pem)
    except InvalidSignature:
        audit(txn_id, "REJECTED_TAMPER", "ECDSA signature invalid — payload tampered")
        save_transaction(payload, sig, "REJECTED")
        return jsonify(error="Signature verification failed — payload was tampered"), 400
    except Exception as e:
        audit(txn_id, "REJECTED_TAMPER", f"Verify error: {e}")
        return jsonify(error="Verification error"), 500

    # Step 5 — commit
    save_nonce(payload["nonce"])
    save_transaction(payload, sig, "ACCEPTED")
    audit(txn_id, "VERIFIED", f"Accepted — {payload['amount']} {payload.get('currency','?')} from {payload['sender']} to {payload['receiver']}")

    return jsonify(
        status="accepted",
        txn_id=txn_id,
        message=f"Transaction verified and committed"
    ), 200


# ── Read endpoints ────────────────────────────────────────────────────────────

@app.route("/transactions", methods=["GET"])
def transactions():
    return jsonify(get_transactions())


@app.route("/transactions/<txn_id>/audit", methods=["GET"])
def txn_audit(txn_id):
    return jsonify(get_audit_log(txn_id))


@app.route("/audit", methods=["GET"])
def full_audit():
    return jsonify(get_audit_log())


@app.route("/users", methods=["GET"])
def users():
    return jsonify(list_users())


# ── Run ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("\n  Fintech Transaction Signing System")
    print("  ─────────────────────────────────────")
    print("  http://localhost:5000\n")
    app.run(debug=True, port=5000)
