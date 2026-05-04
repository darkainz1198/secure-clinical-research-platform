"""
audit.py — Tamper-Evident Audit Logging
ClineaCrypt | WM9PC-15 Applied Cryptography

Every security-relevant action in the system appends an entry to audit.log.
After each write, the SHA-256 hash of the entire log file is updated in
audit.log.hash. The auditor can call verify_log_integrity() to check that
neither the log nor its hash has been modified since the last event.

Events logged:
  STARTUP / SHUTDOWN        System lifecycle
  LOGIN / LOGOUT            Authentication events
  LOGIN_FAIL                Failed login attempt (username withheld — see note)
  LOGIN_FAIL_LOCKOUT        Three consecutive failures
  UPLOAD                    Clinician dataset upload (original + controlled paths)
  RETRIEVE                  Clinician dataset decryption and display
  RETRIEVE_FAILED           Decryption error
  DECRYPT_CONTROLLED        Researcher access to a controlled dataset
  SIGN_FINDINGS             Researcher RSA-PSS signing operation
  VERIFY_SIG                Auditor signature verification (result: VALID/INVALID)
  VERIFY_SIG_MISSING        Auditor attempted verify but .sig file absent
  INTEGRITY_CHECK           Auditor SHA-256 check (result: MATCH/MISMATCH)
  VERIFY_LOG_INTEGRITY      Auditor verifying the log's own rolling hash
  VIEW_LOG                  Auditor reading the log
  ACCESS_DENIED             RBAC violation attempt

Log entry format:
  [YYYY-MM-DD HH:MM:SS] | user=<username> | role=<role> | action=<ACTION> | detail=<free text>

Tamper-evidence mechanism:
  After every log_event() call, the SHA-256 of the complete audit.log file
  is recomputed and written to audit.log.hash. If someone edits audit.log,
  verify_log_integrity() will detect that the hash no longer matches.

  Limitation acknowledged (academic prototype):
    A sophisticated attacker with filesystem access could edit both audit.log
    AND audit.log.hash to cover their tracks. A production system would use
    an append-only log store (e.g. AWS CloudWatch, a WORM drive) or
    HMAC-chain each entry so that modifying any earlier entry breaks all
    subsequent hashes. This lightweight approach is proportionate for the
    prototype scope and is documented as a known limitation.

Privacy note on LOGIN_FAIL:
  Failed login attempts are logged with user='UNKNOWN' rather than the
  username that was typed. This prevents the audit log from accumulating
  valid usernames entered during mistyped login attempts, which would be
  a privacy and security exposure in a real deployment.
"""

import os
import hashlib
from datetime import datetime

BASE_DIR      = os.path.dirname(os.path.abspath(__file__))
LOG_FILE      = os.path.join(BASE_DIR, "data", "logs", "audit.log")
LOG_HASH_FILE = os.path.join(BASE_DIR, "data", "logs", "audit.log.hash")


def _ensure_log_dir() -> None:
    # Create logs directory if missing
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)


def _hash_log_file() -> str:
    # Compute SHA-256 hash of entire audit log file
    if not os.path.exists(LOG_FILE):
        return hashlib.sha256(b"").hexdigest()  # Empty hash if not created yet
    sha256 = hashlib.sha256()
    # Read in chunks to handle large files efficiently
    with open(LOG_FILE, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def log_event(username: str, role: str, action: str, detail: str = "") -> None:
    # Add event to audit log and update rolling hash
    _ensure_log_dir()

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entry = (
        f"[{timestamp}] | user={username} | role={role} | "
        f"action={action} | detail={detail}\n"
    )

    # Append to log (open in append mode — never truncate or overwrite)
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(entry)

    # Update rolling hash so auditor can detect any subsequent modification
    with open(LOG_HASH_FILE, "w") as f:
        f.write(_hash_log_file())


def read_log() -> str:
    # Return all audit log entries
    if not os.path.exists(LOG_FILE):
        return "(Audit log is empty — no events have been recorded yet)"
    with open(LOG_FILE, "r", encoding="utf-8") as f:
        content = f.read()
    return content if content.strip() else "(Audit log is empty)"


def verify_log_integrity() -> tuple[bool, str, str]:
    # Check if audit log has been tampered with
    computed = _hash_log_file()  # Recompute current hash

    if not os.path.exists(LOG_HASH_FILE):
        return False, "NOT FOUND", computed

    with open(LOG_HASH_FILE, "r") as f:
        stored = f.read().strip()

    return (stored == computed), stored, computed
