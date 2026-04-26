"""
main.py — Application Entry Point
ClineaCrypt | WM9PC-15 Applied Cryptography
Module: WM9PC-15 Applied Cryptography — Warwick Manufacturing Group

A local, file-based Python CLI prototype demonstrating a secure
clinical research data-sharing system with three user roles:
  Clinician  — uploads and retrieves encrypted patient datasets
  Researcher — accesses pseudonymised data and signs research findings
  Auditor    — verifies signatures, checks integrity, reviews audit logs

Startup sequence:
  1. Seed test accounts in data/users.json (bcrypt-hashed, first run only)
  2. Generate RSA-2048 key pair for the researcher role (first run only)
  3. Initialise AES-256 keys for both data zones (first run only)
  4. Log a STARTUP event to the audit log
  5. Present the secure login prompt
  6. Dispatch the authenticated user to their role-specific menu

Test accounts (created automatically on first run):
  ┌───────────────────┬────────────────┬────────────┐
  │ Username          │ Password       │ Role       │
  ├───────────────────┼────────────────┼────────────┤
  │ alice_clinician   │ Clinic@123     │ clinician  │
  │ bob_researcher    │ Research@456   │ researcher │
  │ carol_auditor     │ Audit@789      │ auditor    │
  └───────────────────┴────────────────┴────────────┘

Usage:
  pip install cryptography bcrypt
  python main.py

Sample dataset to upload (as Clinician):
  sample_data/patient_dataset_trial1.csv

Sample findings file to sign (as Researcher):
  sample_data/findings_trial1.txt
"""

import sys
from auth import seed_users, login, is_logged_in, get_current_role, get_current_user
from audit import log_event
from menus import clinician_menu, researcher_menu, auditor_menu
from crypto_utils import generate_rsa_keypair, get_original_key, get_controlled_key


def startup_setup() -> None:
    """
    Initialise all system components on first run.

    All operations are idempotent — calling this when the system is already
    configured is a safe no-op (existing files are never overwritten).

    Operations:
      seed_users()              Creates data/users.json with bcrypt-hashed accounts
      generate_rsa_keypair()    Creates data/keys/researcher/private.pem + public.pem
      get_original_key()        Creates data/keys/aes_original.key (32 random bytes)
      get_controlled_key()      Creates data/keys/aes_controlled.key (32 random bytes)
    """
    print()
    print("  ╔══════════════════════════════════════════════════════╗")
    print("  ║        ClineaCrypt — Clinical Cryptosystem           ║")
    print("  ║        WM9PC-15 Applied Cryptography                 ║")
    print("  ╚══════════════════════════════════════════════════════╝")
    print()
    print("  [INIT] Checking system setup...")

    seed_users()              # Create test accounts if absent
    generate_rsa_keypair("researcher")  # Create RSA key pair if absent
    get_original_key()        # Create AES original key if absent
    get_controlled_key()      # Create AES controlled key if absent

    print("  [INIT] All components ready.\n")

    log_event("SYSTEM", "system", "STARTUP", "System initialised")


def login_prompt() -> bool:
    """
    Display the login form and attempt authentication.

    Allows up to 3 consecutive attempts before locking out.
    Returns True on successful login; False after 3 failures.

    Privacy note on failed-attempt logging:
      Failed attempts are logged with user='UNKNOWN' regardless of what was
      typed. Logging the attempted username would gradually expose valid
      usernames to anyone who reads the audit log (e.g. from mistyped logins).
      Only successful logins record the actual username.
    """
    print("=" * 60)
    print("  SECURE LOGIN")
    print("=" * 60)

    for attempt in range(1, 4):
        username = input("\n  Username: ").strip()
        password = input("  Password: ").strip()

        if login(username, password):
            role = get_current_role()
            print(f"\n  [OK] Welcome, {username}. Role: {role}")
            # Log successful login with the real username
            log_event(username, role, "LOGIN", f"attempt={attempt}")
            return True

        remaining = 3 - attempt
        print(f"  [FAIL] Invalid credentials. {remaining} attempt(s) remaining.")

        # Log failure WITHOUT the typed username to protect valid username list
        if attempt < 3:
            log_event("UNKNOWN", "unknown", "LOGIN_FAIL", f"attempt={attempt}")

    print("\n  [LOCKED] Maximum login attempts exceeded.")
    log_event("UNKNOWN", "unknown", "LOGIN_FAIL_LOCKOUT", "3 consecutive failures")
    return False


def dispatch_menu() -> None:
    """
    Route the authenticated session to the correct role menu.

    The role is read from auth.get_current_role() which was set during login
    from the server-side users.json record. It is never derived from user input,
    so a user cannot claim a different role by providing a different string.
    """
    role = get_current_role()

    if role == "clinician":
        clinician_menu()
    elif role == "researcher":
        researcher_menu()
    elif role == "auditor":
        auditor_menu()
    else:
        # Defensive fallback — should never be reached with valid credentials
        print(f"  [ERROR] Unrecognised role '{role}'. Logging out for safety.")
        log_event(get_current_user() or "unknown", role or "unknown", "UNKNOWN_ROLE", "")
        from auth import logout
        logout()


def main() -> None:
    """
    Main application loop.

    Flow:
      startup_setup() → login_prompt() → dispatch_menu() [loop until logout]
                                      ↓
                            offer re-login or exit
    """
    startup_setup()

    while True:
        # Present login; exit if lockout is reached
        if not login_prompt():
            print("\n  Exiting for security.")
            log_event("SYSTEM", "system", "SHUTDOWN", "Post-lockout exit")
            sys.exit(1)

        # Run the role menu until the user logs out
        while is_logged_in():
            dispatch_menu()

        # After a clean logout, offer to login again or exit
        print("\n  [1] Login with a different account")
        print("  [0] Exit")
        again = input("  Choice: ").strip()
        if again != "1":
            print("\n  Goodbye.")
            log_event("SYSTEM", "system", "SHUTDOWN", "Normal exit")
            sys.exit(0)


if __name__ == "__main__":
    main()
