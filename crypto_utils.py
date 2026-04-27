"""
crypto_utils.py — Cryptographic Operations
ClineaCrypt | WM9PC-15 Applied Cryptography

Provides all cryptographic primitives used by the system:

  SYMMETRIC ENCRYPTION  AES-256-GCM via the `cryptography` library
  INTEGRITY HASHING     SHA-256, stored as companion .hash files
  ASYMMETRIC SIGNING    RSA-2048 with PSS padding and SHA-256 digest
  KEY MANAGEMENT        File-based key storage (appropriate for prototype scope)

Algorithm justification summary
  ┌──────────────┬───────────────────────────────────────────────────────┐
  │ AES-256-GCM  │ Provides confidentiality AND authenticated encryption  │
  │              │ in one pass. The 128-bit GCM authentication tag means  │
  │              │ a tampered ciphertext raises InvalidTag on decryption  │
  │              │ rather than silently returning corrupted plaintext.     │
  │              │ GCM is NIST-approved and widely deployed (TLS 1.3).   │
  ├──────────────┼───────────────────────────────────────────────────────┤
  │ Random IV    │ A fresh 96-bit (12-byte) IV is generated per call via  │
  │              │ os.urandom(). Reusing an IV with the same key under    │
  │              │ GCM catastrophically breaks both confidentiality and   │
  │              │ integrity. Random IVs are prepended to the ciphertext. │
  ├──────────────┼───────────────────────────────────────────────────────┤
  │ SHA-256      │ Collision-resistant hash for integrity checking.       │
  │              │ Output is 256 bits (64 hex chars). Stored as companion │
  │              │ .hash files and re-verified by the auditor on demand.  │
  ├──────────────┼───────────────────────────────────────────────────────┤
  │ RSA-2048 PSS │ PSS (Probabilistic Signature Scheme) is preferred over │
  │              │ the older PKCS#1 v1.5 because PSS is provably secure  │
  │              │ under the RSA assumption and uses random padding,      │
  │              │ making each signature unique even for identical input. │
  └──────────────┴───────────────────────────────────────────────────────┘

Key storage (prototype scope):
  AES keys are saved as raw 32-byte binary files in data/keys/.
  RSA keys are saved as PEM files (private + public) per role.
  In a production system these would be stored in an HSM or secrets manager
  and never written to the local filesystem unprotected.
"""

import os
import hashlib

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature

# ── Directory constants ───────────────────────────────────────────────────────
# All paths are relative to the directory containing this file, so the project
# works regardless of where it is cloned or run from.
BASE_DIR       = os.path.dirname(os.path.abspath(__file__))
KEYS_DIR       = os.path.join(BASE_DIR, "data", "keys")
ORIGINAL_DIR   = os.path.join(BASE_DIR, "data", "original")
CONTROLLED_DIR = os.path.join(BASE_DIR, "data", "controlled")
FINDINGS_DIR   = os.path.join(BASE_DIR, "data", "findings")
HASHES_DIR     = os.path.join(BASE_DIR, "data", "hashes")

# Two separate AES key files — one per data zone.
# Using separate keys means that a compromise of the controlled (researcher)
# key does NOT expose the original identifiable patient data.
AES_ORIGINAL_KEY_FILE   = os.path.join(KEYS_DIR, "aes_original.key")
AES_CONTROLLED_KEY_FILE = os.path.join(KEYS_DIR, "aes_controlled.key")
AES_FINDINGS_KEY_FILE   = os.path.join(KEYS_DIR, "aes_findings.key")

# NIST SP 800-38D recommends a 96-bit (12-byte) IV for AES-GCM
AES_IV_SIZE = 12


# ── AES-256 Key Management ────────────────────────────────────────────────────

def load_or_create_aes_key(key_file: str) -> bytes:
    """
    Load a 256-bit AES key from disk, or generate and persist a new one.

    Key generation uses os.urandom(32) which calls the OS CSPRNG
    (e.g. /dev/urandom on Linux, CryptGenRandom on Windows).
    Keys are stored as raw 32-byte binary files.

    This is called once per data zone on startup, so key I/O does not
    add latency to individual encrypt/decrypt operations.
    """
    os.makedirs(os.path.dirname(key_file), exist_ok=True)
    if os.path.exists(key_file):
        with open(key_file, "rb") as f:
            return f.read()
    # Key does not exist yet — generate and save
    key = os.urandom(32)   # 256 bits from OS CSPRNG
    with open(key_file, "wb") as f:
        f.write(key)
    os.chmod(key_file, 0o600)
    return key


def get_original_key() -> bytes:
    """
    Return the AES-256 key for the original (identifiable) patient data zone.
    Only loaded during Clinician operations — Researcher and Auditor roles
    never call this function, so they structurally cannot access the key.
    """
    return load_or_create_aes_key(AES_ORIGINAL_KEY_FILE)


def get_controlled_key() -> bytes:
    """
    Return the AES-256 key for the controlled (pseudonymised) data zone.
    Used by the Clinician to write controlled data and by the Researcher
    to decrypt it. Separate from the original key by design.
    """
    return load_or_create_aes_key(AES_CONTROLLED_KEY_FILE)


def get_findings_key() -> bytes:
    """
    Return the AES-256 key for the findings data zone.
    Used by the Researcher to encrypt and decrypt their findings.
    Separate from other keys for additional security layering.
    """
    return load_or_create_aes_key(AES_FINDINGS_KEY_FILE)


# ── AES-256-GCM Encryption / Decryption ──────────────────────────────────────

def encrypt_data(plaintext: bytes, key: bytes) -> bytes:
    """
    Encrypt plaintext bytes with AES-256-GCM.

    Storage format returned:
      [ 12-byte random IV ] [ variable-length ciphertext + 16-byte GCM tag ]
      └─────────────────────────────────────────────────────────────────────┘
                            single contiguous binary blob

    The IV is prepended so that decrypt_data() can recover it without any
    separate metadata. The GCM authentication tag is appended automatically
    by the cryptography library and verified on decryption.

    A fresh IV is generated for every call: even encrypting the same plaintext
    twice will produce different ciphertext blobs, preventing pattern analysis.
    """
    iv = os.urandom(AES_IV_SIZE)        # Unique nonce for this encryption
    aesgcm = AESGCM(key)
    # encrypt() appends a 16-byte GCM authentication tag to the ciphertext
    ciphertext_with_tag = aesgcm.encrypt(iv, plaintext, None)
    return iv + ciphertext_with_tag     # Prepend IV for recovery at decryption


def decrypt_data(blob: bytes, key: bytes) -> bytes:
    """
    Decrypt a blob produced by encrypt_data().

    The first AES_IV_SIZE bytes are the IV; the remainder is ciphertext+tag.
    AESGCM.decrypt() verifies the GCM authentication tag before returning
    plaintext. If the ciphertext or tag has been modified, it raises
    cryptography.exceptions.InvalidTag, preventing silent data corruption.
    """
    iv         = blob[:AES_IV_SIZE]       # Recover the prepended IV
    ciphertext = blob[AES_IV_SIZE:]       # Remainder: ciphertext + GCM tag
    aesgcm     = AESGCM(key)
    # InvalidTag raised here if blob was tampered — never returns corrupt data
    return aesgcm.decrypt(iv, ciphertext, None)


# ── SHA-256 Integrity Hashing ─────────────────────────────────────────────────

def hash_file(file_path: str) -> str:
    """
    Compute the SHA-256 hash of a file's raw contents.

    Reads in 64 KiB chunks to handle large files without loading them fully
    into memory. Returns the lowercase hex-encoded 256-bit digest string
    (64 characters).
    """
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def _hash_key_for(file_path: str) -> str:
    """
    Build a namespace-safe key for the companion .hash filename.

    Problem solved: two files can share the same basename but live in
    different directories — e.g.
      data/original/dataset.enc   and
      data/controlled/dataset.enc
    Without namespacing, both would map to 'dataset.enc.hash' in HASHES_DIR
    and the second write would silently overwrite the first, making integrity
    checks unreliable.

    Solution: prefix the hash filename with the immediate parent directory name.
      data/original/dataset.enc   → original__dataset.enc.hash
      data/controlled/dataset.enc → controlled__dataset.enc.hash
      data/findings/report.txt    → findings__report.txt.hash
    """
    parent   = os.path.basename(os.path.dirname(os.path.abspath(file_path)))
    basename = os.path.basename(file_path)
    return f"{parent}__{basename}"


def save_hash(file_path: str, hash_hex: str) -> str:
    """
    Write a SHA-256 hex digest to a companion .hash file in HASHES_DIR.

    The hash filename is namespaced by parent directory (see _hash_key_for)
    to prevent collisions between files with identical names in different zones.
    Returns the full path of the written .hash file.
    """
    os.makedirs(HASHES_DIR, exist_ok=True)
    key       = _hash_key_for(file_path)
    hash_path = os.path.join(HASHES_DIR, key + ".hash")
    with open(hash_path, "w") as f:
        f.write(hash_hex)
    return hash_path


def verify_integrity(file_path: str) -> tuple[bool, str, str]:
    """
    Re-compute the SHA-256 hash of file_path and compare it against the
    companion hash stored during initial write.

    Returns a 3-tuple:
      (match: bool, stored_hash: str, computed_hash: str)

    If no companion hash file exists (file was not registered at write time),
    returns (False, 'NOT FOUND', computed_hash).

    A mismatch indicates the file has been modified since it was stored —
    either corruption or deliberate tampering.
    """
    key       = _hash_key_for(file_path)
    hash_path = os.path.join(HASHES_DIR, key + ".hash")
    computed  = hash_file(file_path)

    if not os.path.exists(hash_path):
        return False, "NOT FOUND", computed

    with open(hash_path, "r") as f:
        stored = f.read().strip()

    return (stored == computed), stored, computed


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
    """Load and return the RSA private key PEM for the given role."""
    with open(_rsa_private_key_path(role), "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def load_public_key(role: str) -> RSAPublicKey:
    """Load and return the RSA public key PEM for the given role."""
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
            mgf=padding.MGF1(hashes.SHA256()),  # Mask generation function
            salt_length=padding.PSS.MAX_LENGTH, # Maximum salt for strongest security
        ),
        hashes.SHA256(),                         # Hash algorithm for digest
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
