"""
auth.py — Authentication and Role-Based Access Control (RBAC)
ClineaCrypt | WM9PC-15 Applied Cryptography

Responsibilities:
  - Secure password hashing and verification using bcrypt
  - Persistent credential storage in data/users.json
  - Session management: tracks which user is currently logged in
  - RBAC enforcement: maps each role to its permitted operations
  - Test account seeding on first run (one account per role)

Security design notes:
  ┌─────────────────────────────────────────────────────────────────┐
  │ PASSWORDS                                                       │
  │   Never stored in plaintext. bcrypt.hashpw() is called with    │
  │   bcrypt.gensalt() which generates a unique 128-bit random salt │
  │   per account. The salt is embedded in the stored hash string,  │
  │   so no separate salt file is needed.                           │
  │                                                                 │
  │ TIMING ATTACK PREVENTION                                        │
  │   When a username does not exist, a dummy bcrypt.checkpw() call │
  │   is still made so that the response time is indistinguishable  │
  │   from a valid-username/wrong-password failure. Without this,   │
  │   an attacker could enumerate valid usernames by measuring       │
  │   response time.                                                │
  │                                                                 │
  │ ROLE TRUST                                                      │
  │   The role is read from users.json (server-side store), never   │
  │   from user input. A user cannot claim or escalate their role.  │
  │                                                                 │
  │ SESSION SCOPE                                                   │
  │   Session state lives in module-level variables. This is        │
  │   appropriate for a single-process CLI prototype. A web or      │
  │   multi-user system would use signed session tokens instead.    │
  └─────────────────────────────────────────────────────────────────┘
"""

import json
import os
import bcrypt

# ── Credential store path ─────────────────────────────────────────────────────
USERS_FILE = os.path.join(os.path.dirname(__file__), "data", "users.json")

# ── RBAC permission map ───────────────────────────────────────────────────────
# Each role is mapped to the set of action strings it is permitted to perform.
# Menus and individual operation handlers both check has_permission() against
# this map, providing two independent layers of access enforcement.
#
# To add a new role: add a key here and create a corresponding menu branch
# in menus.py. No other changes are needed.
ROLE_PERMISSIONS = {
    "clinician": {
        "upload_dataset",    # Encrypt and store an original patient dataset
        "retrieve_dataset",  # Decrypt and read back an original dataset
        "list_original",     # List files stored in data/original/
    },
    "researcher": {
        "list_controlled",   # List available pseudonymised datasets
        "decrypt_controlled",# Decrypt a controlled (de-identified) dataset
        "sign_findings",     # Digitally sign a research findings document
        "list_findings",     # List stored findings files
    },
    "auditor": {
        "verify_signature",  # Verify an RSA-PSS digital signature
        "check_integrity",   # Re-hash a file and compare against stored hash
        "view_audit_log",    # Read the tamper-evident audit log
        "list_all_files",    # List all files across every storage zone
    },
}

# ── Session state ─────────────────────────────────────────────────────────────
# Held in module-level variables. Only one user is active at a time.
_current_user: str | None = None
_current_role: str | None = None


def get_current_user() -> str | None:
    """Return the username of the currently authenticated user, or None."""
    return _current_user


def get_current_role() -> str | None:
    """Return the role of the currently authenticated user, or None."""
    return _current_role


def is_logged_in() -> bool:
    """Return True if a user is currently authenticated."""
    return _current_user is not None


def has_permission(action: str) -> bool:
    """
    Return True if the active session's role is authorised to perform action.
    Returns False if no user is logged in or the action is not in their set.
    """
    if _current_role is None:
        return False
    return action in ROLE_PERMISSIONS.get(_current_role, set())


# ── Credential store helpers ──────────────────────────────────────────────────

def _load_users() -> dict:
    """
    Load users.json from disk.
    Returns an empty dict if the file does not exist yet (first-run case).
    """
    if not os.path.exists(USERS_FILE):
        return {}
    with open(USERS_FILE, "r") as f:
        return json.load(f)


def _save_users(users: dict) -> None:
    """Write the credential dict to users.json, creating parent dirs if needed."""
    os.makedirs(os.path.dirname(USERS_FILE), exist_ok=True)
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=2)


# ── Test account definitions ──────────────────────────────────────────────────
# One account per role, as required by the assignment brief (Task 2).
# Plaintext passwords are only held here in source; they are hashed immediately
# during seeding and never written to disk in cleartext.
TEST_ACCOUNTS = [
    # (username,          plaintext_password,  role)
    ("alice_clinician",  "Clinic@123",         "clinician"),
    ("bob_researcher",   "Research@456",       "researcher"),
    ("carol_auditor",    "Audit@789",          "auditor"),
]


def seed_users() -> None:
    """
    Create the three test accounts if users.json does not yet exist.

    Each password is hashed with bcrypt before writing to disk:
      bcrypt.hashpw(password, bcrypt.gensalt())
        → generates a unique 128-bit salt
        → applies the Blowfish-based bcrypt KDF with cost factor 12
        → returns a 60-character hash string that embeds the salt

    This function is idempotent: calling it when users.json already exists
    does nothing, preserving any accounts created later.
    """
    if os.path.exists(USERS_FILE):
        return  # Already seeded — do not overwrite existing credentials

    users = {}
    for username, password, role in TEST_ACCOUNTS:
        # gensalt() default cost=12 means 2^12 = 4096 bcrypt iterations,
        # making brute-force attacks computationally expensive.
        hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
        users[username] = {
            "password_hash": hashed.decode("utf-8"),  # Store as UTF-8 string
            "role": role,
        }

    _save_users(users)
    print("[AUTH] Test accounts created (passwords bcrypt-hashed).")


# ── Login / Logout ────────────────────────────────────────────────────────────

def login(username: str, password: str) -> bool:
    """
    Verify credentials and establish a session if they are correct.

    Returns True on success (session variables are set).
    Returns False on any failure without indicating which field was wrong,
    to prevent username enumeration attacks.

    The timing-safe dummy check ensures response time is constant whether
    the username exists or not.
    """
    global _current_user, _current_role

    users = _load_users()
    record = users.get(username)

    if record is None:
        # Username not found — perform a dummy bcrypt call to equalise timing.
        # Without this, absent-username responses would be ~100× faster than
        # wrong-password responses, leaking which usernames are valid.
        bcrypt.checkpw(password.encode("utf-8"),
                       bcrypt.hashpw(b"dummy_timing_equaliser", bcrypt.gensalt()))
        return False

    stored_hash = record["password_hash"].encode("utf-8")
    if not bcrypt.checkpw(password.encode("utf-8"), stored_hash):
        return False  # Correct username, wrong password

    # Both checks passed — establish session
    _current_user = username
    _current_role = record["role"]
    return True


def logout() -> None:
    """
    Terminate the current session by clearing all session variables.
    The next operation will require a fresh login.
    """
    global _current_user, _current_role
    _current_user = None
    _current_role = None


# ── RBAC decorator (optional — used for belt-and-braces protection) ───────────

def require_permission(action: str):
    """
    Decorator factory that guards a function with an RBAC check.
    Raises PermissionError if the current session lacks the required permission.

    Usage:
        @require_permission("upload_dataset")
        def upload():
            ...

    Note: The menus already enforce RBAC at the menu-dispatch level.
    This decorator adds a second, function-level guard so that operations
    remain protected even if called directly (e.g. from tests or the REPL).
    """
    def decorator(func):
        def wrapper(*args, **kwargs):
            if not has_permission(action):
                raise PermissionError(
                    f"[RBAC] '{action}' is not permitted for role '{_current_role}'."
                )
            return func(*args, **kwargs)
        return wrapper
    return decorator
