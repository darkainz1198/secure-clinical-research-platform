"""
ClineaCrypt - Clinical data sharing system with encryption
Three user roles: Clinician, Researcher, Auditor

Test accounts (auto-created on first run):
  Sri_clinician / Clinic@123
  Sri_researcher / Research@456
  SAV_researcher / SAVResearch@789
  Sri_auditor / Audit@789
"""

import sys
from auth import seed_users, login, is_logged_in, get_current_role, get_current_user
from audit import log_event
from menus import clinician_menu, researcher_menu, auditor_menu
from crypto_utils import generate_rsa_keypair, get_original_key, get_controlled_key, get_findings_key
import getpass


def startup_setup() -> None:
    # Initialize system: create users, keys, and encryption setup on first run
    print()
    print("  ╔══════════════════════════════════════════════════════╗")
    print("  ║        ClineaCrypt — Clinical Cryptosystem           ║")
    print("  ║        WM9PC-15 Applied Cryptography                 ║")
    print("  ╚══════════════════════════════════════════════════════╝")
    print()
    print("  [INIT] Checking system setup...")

    # Create all necessary files and keys
    seed_users()  # Create user accounts
    generate_rsa_keypair("researcher")  # RSA for signing
    get_original_key()  # Clinician data key
    get_controlled_key()  # Researcher data key
    get_findings_key()  # Findings data key

    print("  [INIT] All components ready.\n")

    log_event("SYSTEM", "system", "STARTUP", "System initialised")


def login_prompt() -> bool:
    # Show login screen, allow 3 attempts, return True if successful
    print("=" * 60)
    print("  SECURE LOGIN")
    print("=" * 60)

    for attempt in range(1, 4):
        # Get credentials from user
        username = input("\n  Username: ").strip()
        password = getpass.getpass("  Password: ").strip()

        if login(username, password):
            # Login successful
            role = get_current_role()
            print(f"\n  [OK] Welcome, {username}. Role: {role}")
            log_event(username, role, "LOGIN", f"attempt={attempt}")
            return True

        # Login failed
        remaining = 3 - attempt
        print(f"  [FAIL] Invalid credentials. {remaining} attempt(s) remaining.")
        if attempt < 3:
            log_event("UNKNOWN", "unknown", "LOGIN_FAIL", f"attempt={attempt}")

    print("\n  [LOCKED] Maximum login attempts exceeded.")
    log_event("UNKNOWN", "unknown", "LOGIN_FAIL_LOCKOUT", "3 consecutive failures")
    return False


def dispatch_menu() -> None:
    # Send user to their role-specific menu
    role = get_current_role()

    # Route to appropriate menu based on role
    if role == "clinician":
        clinician_menu()
    elif role == "researcher":
        researcher_menu()
    elif role == "auditor":
        auditor_menu()
    else:
        # Should never happen with valid credentials
        print(f"  [ERROR] Unrecognised role '{role}'. Logging out.")
        log_event(get_current_user() or "unknown", role or "unknown", "UNKNOWN_ROLE", "")
        from auth import logout
        logout()


def main() -> None:
    # Main app loop: setup, login, show menu
    startup_setup()  # Initialize on first run

    while True:
        # Login with 3 attempt limit
        if not login_prompt():
            print("\n  Exiting for security.")
            log_event("SYSTEM", "system", "SHUTDOWN", "Post-lockout exit")
            sys.exit(1)
        
        # Show menu until user logs out
        while is_logged_in():
            dispatch_menu()
        
        # After logout, ask if user wants to login again
        print("\n  [1] Login with a different account")
        print("  [0] Exit")
        again = input("  Choice: ").strip()
        if again != "1":
            print("\n  Goodbye.")
            log_event("SYSTEM", "system", "SHUTDOWN", "Normal exit")
            sys.exit(0)


if __name__ == "__main__":
    main()
