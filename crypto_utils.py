"""
Encryption, hashing, and digital signatures
AES-256-GCM for data encryption, SHA-256 for integrity, RSA-2048 for signing
"""

import os
import hashlib

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature

# Directory structure
BASE_DIR       = os.path.dirname(os.path.abspath(__file__))
KEYS_DIR       = os.path.join(BASE_DIR, "data", "keys")
ORIGINAL_DIR   = os.path.join(BASE_DIR, "data", "original")
CONTROLLED_DIR = os.path.join(BASE_DIR, "data", "controlled")
FINDINGS_DIR   = os.path.join(BASE_DIR, "data", "findings")
HASHES_DIR     = os.path.join(BASE_DIR, "data", "hashes")

# Separate AES keys for each data zone
AES_ORIGINAL_KEY_FILE   = os.path.join(KEYS_DIR, "aes_original.key")
AES_CONTROLLED_KEY_FILE = os.path.join(KEYS_DIR, "aes_controlled.key")
AES_FINDINGS_KEY_FILE   = os.path.join(KEYS_DIR, "aes_findings.key")

AES_IV_SIZE = 12


# Key management
def load_or_create_aes_key(key_file: str) -> bytes:
    # Load or create a 256-bit AES key from file
    os.makedirs(os.path.dirname(key_file), exist_ok=True)
    if os.path.exists(key_file):
        # Key already exists, load it
        with open(key_file, "rb") as f:
            return f.read()
    # Generate new random key on first run
    key = os.urandom(32)  # 256 bits
    with open(key_file, "wb") as f:
        f.write(key)
    os.chmod(key_file, 0o600)  # Restrict permissions
    return key


def get_original_key() -> bytes:
    # Get the key for original patient data
    return load_or_create_aes_key(AES_ORIGINAL_KEY_FILE)

def get_controlled_key() -> bytes:
    # Get the key for pseudonymised data
    return load_or_create_aes_key(AES_CONTROLLED_KEY_FILE)

def get_findings_key() -> bytes:
    # Get the key for researcher findings
    return load_or_create_aes_key(AES_FINDINGS_KEY_FILE)


# Encryption and decryption
def encrypt_data(plaintext: bytes, key: bytes) -> bytes:
    # Encrypt with AES-256-GCM, return IV + ciphertext
    iv = os.urandom(AES_IV_SIZE)  # Fresh random IV per encryption
    aesgcm = AESGCM(key)
    ciphertext_with_tag = aesgcm.encrypt(iv, plaintext, None)  # GCM adds authentication tag
    return iv + ciphertext_with_tag  # IV needed for decryption


def decrypt_data(blob: bytes, key: bytes) -> bytes:
    # Decrypt, verify tag, return plaintext
    iv = blob[:AES_IV_SIZE]  # Extract IV from start
    ciphertext = blob[AES_IV_SIZE:]  # Remaining is ciphertext + tag
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(iv, ciphertext, None)  # Raises error if tampered


# Hashing
def hash_file(file_path: str) -> str:
    # Compute SHA-256 hash of file
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def _hash_key_for(file_path: str) -> str:
    # Build namespace-safe hash filename
    parent   = os.path.basename(os.path.dirname(os.path.abspath(file_path)))
    basename = os.path.basename(file_path)
    return f"{parent}__{basename}"


def save_hash(file_path: str, hash_hex: str) -> str:
    # Save hash to file
    os.makedirs(HASHES_DIR, exist_ok=True)
    key       = _hash_key_for(file_path)
    hash_path = os.path.join(HASHES_DIR, key + ".hash")
    with open(hash_path, "w") as f:
        f.write(hash_hex)
    return hash_path


def verify_integrity(file_path: str) -> tuple[bool, str, str]:
    # Compare stored hash with computed hash, return (match, stored, computed)
    key       = _hash_key_for(file_path)
    hash_path = os.path.join(HASHES_DIR, key + ".hash")
    computed  = hash_file(file_path)  # Recompute current hash

    if not os.path.exists(hash_path):
        return False, "NOT FOUND", computed  # No stored hash to compare

    with open(hash_path, "r") as f:
        stored = f.read().strip()  # Load stored hash

    return (stored == computed), stored, computed  # True if unchanged


# ── RSA-2048 Key Pair Management ─────────────────────────────────────────────

def _rsa_private_key_path(role: str) -> str:
    return os.path.join(KEYS_DIR, role, "private.pem")


def _rsa_public_key_path(role: str) -> str:
    return os.path.join(KEYS_DIR, role, "public.pem")


def generate_rsa_keypair(role: str) -> None:
    """
    Generate a 2048-bit RSA key pair for the given role and save as PEM files.

    Key parameters:
      Key size      : 2048 bits (minimum recommended; adequate for a prototype)
      Public exponent: 65537 (standard Fermat prime; balances security/speed)

    The private key is saved without a passphrase for demonstration simplicity.
    In a production system the private key would be passphrase-protected or
    stored in a hardware security module (HSM).

    This function is idempotent: calling it when the PEM file already exists
    is a no-op, so the same key pair is used across sessions.
    """
    priv_path = _rsa_private_key_path(role)
    if os.path.exists(priv_path):
        return  # Key pair already present — do not overwrite

    os.makedirs(os.path.dirname(priv_path), exist_ok=True)

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key  = private_key.public_key()

    # Write private key in PEM / TraditionalOpenSSL format (unencrypted)
    with open(priv_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    os.chmod(priv_path, 0o600)

    # Write public key in PEM / SubjectPublicKeyInfo format
    pub_path = _rsa_public_key_path(role)
    with open(pub_path, "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ))

    print(f"[CRYPTO] RSA-2048 key pair generated for role '{role}'.")


def load_private_key(role: str) -> RSAPrivateKey:
    # Load RSA private key from PEM
    with open(_rsa_private_key_path(role), "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def load_public_key(role: str) -> RSAPublicKey:
    # Load RSA public key from PEM
    with open(_rsa_public_key_path(role), "rb") as f:
        return serialization.load_pem_public_key(f.read())


# ── RSA-PSS Digital Signing and Verification ─────────────────────────────────

def sign_file(file_path: str, role: str) -> str:
    """
    Produce an RSA-PSS digital signature over the contents of file_path.

    Why RSA-PSS over PKCS#1 v1.5?
      PSS (Probabilistic Signature Scheme) uses random salt in the padding,
      so two signatures of the same file differ each time. PKCS#1 v1.5 is
      deterministic and has known theoretical weaknesses. PSS has a tight
      security reduction to the RSA problem and is required by FIPS 186-5.

    Process:
      1. Read file contents into memory
      2. Sign with private_key.sign(), which internally:
           a. Hashes content with SHA-256
           b. Applies PSS padding with random MAX_LENGTH salt
           c. Applies RSA private-key operation
      3. Write the 256-byte signature blob to <file_path>.sig

    Returns the path of the written .sig file.
    """
    private_key = load_private_key(role)

    with open(file_path, "rb") as f:
        content = f.read()

    signature = private_key.sign(
        content,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )

    sig_path = file_path + ".sig"
    with open(sig_path, "wb") as f:
        f.write(signature)

    return sig_path


def verify_signature(file_path: str, sig_path: str, role: str) -> bool:
    """
    Verify an RSA-PSS signature against a file using the role's public key.

    A True return proves two things simultaneously:
      1. Authenticity — the signature was created by the private key holder
         (only the researcher has access to data/keys/researcher/private.pem)
      2. Integrity — the file has not been modified since it was signed
         (any byte change would produce a different hash, failing verification)

    Returns False (not an exception) on verification failure so that the
    auditor menu can display a clear INVALID message rather than crashing.
    """
    public_key = load_public_key(role)

    with open(file_path, "rb") as f:
        content = f.read()
    with open(sig_path, "rb") as f:
        signature = f.read()

    try:
        public_key.verify(
            signature,
            content,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True   # Signature valid — file is authentic and unmodified

    except InvalidSignature:
        return False  # Signature invalid or file content has changed
