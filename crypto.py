"""
crypto.py — ECDSA key generation, transaction signing, and verification.
SHA-256 is used as the payload digest (required by ECDSA).
bcrypt is used to protect the passphrase that encrypts the private key.
"""

import json
import hashlib
import bcrypt
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, Prehashed
from cryptography.exceptions import InvalidSignature


# ── Key generation ────────────────────────────────────────────────────────────

def generate_keypair(user_password: str) -> tuple[bytes, bytes, bytes]:
    """
    Generate an ECDSA P-256 keypair.

    Returns:
        encrypted_private_pem  — AES-256-encrypted PEM (safe to store in DB)
        public_pem             — plaintext PEM (store openly in DB)
        bcrypt_hash            — bcrypt hash of the password (store in DB)

    The private key is encrypted with the raw user_password as passphrase.
    The bcrypt hash is stored separately so we can verify the password on login
    before attempting to decrypt the private key.
    """
    # 1. Bcrypt the password — this is what goes in the DB for auth checks
    bcrypt_hash = bcrypt.hashpw(user_password.encode(), bcrypt.gensalt())

    # 2. Generate the ECDSA P-256 private key
    private_key = ec.generate_private_key(ec.SECP256R1())

    # 3. Serialize private key — encrypted with AES-256-CBC using password as passphrase
    #    BestAvailableEncryption picks AES-256-CBC (PKCS8 standard)
    encrypted_private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(user_password.encode())
    )

    # 4. Serialize public key — plaintext, safe to store and share
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return encrypted_private_pem, public_pem, bcrypt_hash


def verify_password(user_password: str, bcrypt_hash: bytes) -> bool:
    """Check user_password against the stored bcrypt hash."""
    return bcrypt.checkpw(user_password.encode(), bcrypt_hash)


# ── Canonical serialization ───────────────────────────────────────────────────

def canonical_bytes(payload: dict) -> bytes:
    """
    Deterministic JSON serialization — same input always produces same bytes.
    Keys sorted alphabetically, no whitespace, UTF-8 encoded.
    This is what gets hashed and signed.
    """
    return json.dumps(payload, sort_keys=True, separators=(',', ':')).encode('utf-8')


# ── Signing ───────────────────────────────────────────────────────────────────

def sign_transaction(payload: dict, encrypted_private_pem: bytes, user_password: str) -> str:
    """
    Sign a transaction payload.

    Flow:
        payload → canonical JSON → SHA-256 digest → ECDSA sign → hex signature

    SHA-256 is mandatory here — ECDSA operates on a fixed-size digest,
    not the raw payload. bcrypt cannot be used here because it is non-deterministic
    (different output each call), which would break verification.

    Returns:
        Hex-encoded DER signature string.
    """
    # Load and decrypt the private key using the user's password as passphrase
    private_key = serialization.load_pem_private_key(
        encrypted_private_pem,
        password=user_password.encode()
    )

    # SHA-256 digest of the canonical payload
    digest = hashlib.sha256(canonical_bytes(payload)).digest()

    # ECDSA sign — Prehashed tells the library we already computed the digest
    signature_bytes = private_key.sign(digest, ec.ECDSA(Prehashed(hashes.SHA256())))

    return signature_bytes.hex()


# ── Verification ──────────────────────────────────────────────────────────────

def verify_transaction(payload: dict, signature_hex: str, public_pem: bytes) -> bool:
    """
    Verify a transaction signature.

    Flow:
        payload → canonical JSON → SHA-256 digest → ECDSA verify (using public key)

    Returns True if valid. Raises InvalidSignature if the payload was tampered
    or the signature is forged.
    """
    public_key = serialization.load_pem_public_key(public_pem)

    digest = hashlib.sha256(canonical_bytes(payload)).digest()

    try:
        public_key.verify(bytes.fromhex(signature_hex), digest, ec.ECDSA(Prehashed(hashes.SHA256())))
        return True
    except InvalidSignature:
        raise
    except Exception as e:
        raise InvalidSignature(f"Verification error: {e}")
