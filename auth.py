"""
User authentication, password hashing, and role-based access control
"""

import json
import os
import bcrypt

USERS_FILE = os.path.join(os.path.dirname(__file__), "data", "users.json")

# Define what each role can do
ROLE_PERMISSIONS = {
    "clinician": {
        "upload_dataset",
        "retrieve_dataset",
        "list_original",
    },
    "researcher": {
        "list_controlled",
        "decrypt_controlled",
        "sign_findings",
        "list_findings",
    },
    "auditor": {
        "verify_signature",
        "check_integrity",
        "view_audit_log",
        "list_all_files",
    },
}

# Track current logged-in user and their role
_current_user: str | None = None
_current_role: str | None = None


def get_current_user() -> str | None:
    # Return logged-in username or None
    return _current_user


def get_current_role() -> str | None:
    # Return logged-in user's role or None
    return _current_role


def is_logged_in() -> bool:
    # Return True if someone is logged in
    return _current_user is not None


def has_permission(action: str) -> bool:
    # Check if logged-in user can do this action
    if _current_role is None:
        return False
    return action in ROLE_PERMISSIONS.get(_current_role, set())


# ── Credential store helpers ──────────────────────────────────────────────────

def _load_users() -> dict:
    # Load user credentials from file
    if not os.path.exists(USERS_FILE):
        return {}
    with open(USERS_FILE, "r") as f:
        return json.load(f)


def _save_users(users: dict) -> None:
    # Save user credentials to file
    os.makedirs(os.path.dirname(USERS_FILE), exist_ok=True)
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=2)


# Test accounts (auto-created on first run)
TEST_ACCOUNTS = [
    ("Sri_clinician",    "Clinic@123",         "clinician"),
    ("Sri_researcher",   "Research@456",       "researcher"),
    ("SAV_researcher",   "SAVResearch@789",    "researcher"),
    ("Sri_auditor",      "Audit@789",          "auditor"),
]


def seed_users() -> None:
    # Create test accounts on first run, hash passwords with bcrypt
    if os.path.exists(USERS_FILE):
        return  # Already done, don't overwrite

    users = {}
    for username, password, role in TEST_ACCOUNTS:
        # Hash password with bcrypt using random salt
        hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
        users[username] = {
            "password_hash": hashed.decode("utf-8"),  # Store as string
            "role": role,
        }

    _save_users(users)
    print("[AUTH] Test accounts created (passwords bcrypt-hashed).")


# ── Login / Logout ────────────────────────────────────────────────────────────

def login(username: str, password: str) -> bool:
    # Verify credentials, set session if correct
    global _current_user, _current_role

    users = _load_users()
    record = users.get(username)

    if record is None:
        # Username doesn't exist - do dummy check to prevent timing attacks
        bcrypt.checkpw(password.encode("utf-8"),
                       bcrypt.hashpw(b"dummy_timing_equaliser", bcrypt.gensalt()))
        return False

    # Check password against stored bcrypt hash
    stored_hash = record["password_hash"].encode("utf-8")
    if not bcrypt.checkpw(password.encode("utf-8"), stored_hash):
        return False  # Wrong password

    # Success - establish session
    _current_user = username
    _current_role = record["role"]
    return True


def logout() -> None:
    # Clear session: end current login
    global _current_user, _current_role
    _current_user = None
    _current_role = None


# ── RBAC decorator (optional — used for belt-and-braces protection) ───────────

def require_permission(action: str):
    # Decorator to protect functions with permission check
    def decorator(func):
        def wrapper(*args, **kwargs):
            if not has_permission(action):
                raise PermissionError(
                    f"[RBAC] '{action}' is not permitted for role '{_current_role}'."
                )
            return func(*args, **kwargs)
        return wrapper
    return decorator
