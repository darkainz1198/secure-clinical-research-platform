"""
menus.py — Role-Specific CLI Menus
ClineaCrypt | WM9PC-15 Applied Cryptography

Presents a numbered-option menu for each role and dispatches user choices
to the appropriate operation handler.

RBAC is enforced at two independent levels:
  Level 1 — Menu display: only options permitted for the active role are shown
  Level 2 — Operation handler: every handler calls has_permission() before
             executing, providing a second independent guard

New features in this version:
  FEATURE 1 — Researcher findings: two input methods
    Option A: Type findings directly in the terminal
    Option B: Load findings from a .txt file on disk
    Findings creation and digital signing are clearly separated:
    the researcher first saves findings (option 3), then signs them (option 4).

  FEATURE 2 — Clinician assigns a researcher to each dataset
    During upload, the Clinician selects one researcher account from the
    list of registered researchers. Only that researcher can decrypt the
    controlled copy. Any other researcher is denied and the event is logged.
"""

import os
import datetime

from auth import get_current_user, get_current_role, has_permission, logout
from storage import (
    store_original_dataset, retrieve_original_dataset,
    retrieve_controlled_dataset, store_findings,
    list_original_datasets, list_controlled_datasets,
    list_findings, list_all_stored_files,
    FINDINGS_DIR,
)
from crypto_utils import (
    sign_file, verify_signature,
    verify_integrity as crypto_verify_integrity,
    ORIGINAL_DIR, CONTROLLED_DIR, HASHES_DIR,
)
from audit import log_event, read_log, verify_log_integrity
from assignments import (
    get_researcher_usernames, list_assignments, get_assigned_researcher,
)


# ── Shared display helpers ────────────────────────────────────────────────────

def _print_header(title: str) -> None:
    """Print a consistent section header showing the active user and role."""
    print("\n" + "=" * 60)
    print(f"  {title}")
    print(f"  Logged in as: {get_current_user()} [{get_current_role()}]")
    print("=" * 60)


def _pick_file(file_list: list[str], prompt: str) -> str | None:
    """
    Display a numbered list of filenames and return the chosen one.
    Returns None if the list is empty or the user enters 0 to cancel.
    """
    if not file_list:
        print("  (No files available)")
        return None
    for i, name in enumerate(file_list, 1):
        print(f"  [{i}] {name}")
    try:
        choice = int(input(f"\n{prompt} (0 to cancel): "))
        if choice == 0:
            return None
        return file_list[choice - 1]
    except (ValueError, IndexError):
        print("  Invalid selection.")
        return None


def _pick_researcher() -> str | None:
    """
    Display registered researcher accounts and return the chosen username.
    Returns None if no researchers exist or the user cancels.
    Used by the Clinician upload flow to assign a specific researcher.
    """
    researchers = get_researcher_usernames()
    if not researchers:
        print("  [WARN] No researcher accounts found in the system.")
        return None
    print("\n  Registered researcher accounts:")
    for i, username in enumerate(researchers, 1):
        print(f"  [{i}] {username}")
    try:
        choice = int(input("\n  Assign dataset to researcher (0 to cancel): "))
        if choice == 0:
            return None
        return researchers[choice - 1]
    except (ValueError, IndexError):
        print("  Invalid selection.")
        return None


# ── Clinician menu ────────────────────────────────────────────────────────────

def clinician_menu() -> None:
    """
    Main loop for the Clinician role.

    Available operations:
      [1] Upload encrypted patient dataset  (with researcher assignment)
      [2] Retrieve / decrypt patient dataset
      [3] List stored datasets
      [4] View dataset-researcher assignments
      [5] Enter patient data manually
      [0] Logout
    """
    while True:
        _print_header("CLINICIAN PORTAL")
        print("  [1] Upload encrypted patient dataset")
        print("  [2] Retrieve / decrypt patient dataset")
        print("  [3] List stored datasets")
        print("  [4] View dataset-researcher assignments")
        print("  [5] Enter patient data manually")
        print("  [0] Logout")

        choice = input("\nSelect option: ").strip()
        if choice == "1":
            _clinician_upload()
        elif choice == "2":
            _clinician_retrieve()
        elif choice == "3":
            _clinician_list()
        elif choice == "4":
            _clinician_view_assignments()
        elif choice == "5":
            _clinician_manual_entry()
        elif choice == "0":
            log_event(get_current_user(), get_current_role(), "LOGOUT", "")
            logout()
            print("\n  Logged out successfully.")
            break
        else:
            print("  Invalid option.")


def _clinician_upload() -> None:
    """
    Encrypt a patient dataset, pseudonymise it, and assign it to a researcher.

    FEATURE 2 — Researcher assignment:
      After selecting the file, the Clinician picks one researcher from the
      registered accounts. Only that researcher can decrypt the controlled copy.
      The assignment is stored in data/assignments.json and enforced at runtime.

    Validation:
      - File must exist at the path entered
      - File must not be empty
      - A researcher must be selected before upload proceeds
    """
    if not has_permission("upload_dataset"):
        print("  [RBAC] Access denied.")
        return

    # ── Get and validate the file path ────────────────────────────────────
    filepath = input("\n  Path to patient dataset file (CSV or TXT): ").strip()
    if not filepath:
        print("  Cancelled.")
        return
    if not os.path.isfile(filepath):
        print(f"  [ERROR] File not found: '{filepath}'")
        return

    filename = os.path.basename(filepath)
    with open(filepath, "rb") as f:
        plaintext = f.read()

    if not plaintext:
        print("  [ERROR] File is empty.")
        return

    # ── Assign a researcher (FEATURE 2) ───────────────────────────────────
    print(f"\n  File '{filename}' ready.")
    print("  Assign this dataset to a specific researcher.")
    print("  Only the assigned researcher will be able to access the controlled copy.")

    assigned_researcher = _pick_researcher()
    if assigned_researcher is None:
        print("  Upload cancelled — no researcher assigned.")
        return

    # ── Encrypt, pseudonymise, store, record assignment ───────────────────
    print(f"\n  Encrypting '{filename}' with AES-256-GCM...")
    original_path, controlled_path = store_original_dataset(
        plaintext, filename, assigned_researcher
    )

    print(f"\n  [OK] Original stored    : {original_path}")
    print(f"  [OK] Controlled stored  : {controlled_path}")
    print(f"  [OK] Assigned researcher: {assigned_researcher}")
    print(f"  [OK] SHA-256 hashes saved")

    log_event(
        get_current_user(), get_current_role(), "UPLOAD",
        f"file={filename} | assigned_to={assigned_researcher}",
    )
    print("  [OK] Audit log updated.")


def _clinician_manual_entry() -> None:
    """
    Manually enter patient data field by field, then encrypt and store it.

    Asks for each field one by one, creates a CSV dataset, and assigns it to a researcher.
    """
    if not has_permission("upload_dataset"):
        print("  [RBAC] Access denied.")
        return

    print("\n  Enter patient data manually. Please provide the following fields:")

    patient_id = input("  Patient ID: ").strip()
    name = input("  Name: ").strip()
    nhs_number = input("  NHS Number: ").strip()
    dob = input("  Date of Birth (YYYY-MM-DD): ").strip()
    postcode = input("  Postcode: ").strip()
    diagnosis = input("  Diagnosis: ").strip()
    test_result = input("  Test Result: ").strip()
    medication = input("  Medication: ").strip()
    visit_date = input("  Visit Date (YYYY-MM-DD): ").strip()

    # Create CSV content
    header = "patient_id,name,nhs_number,dob,postcode,diagnosis,test_result,medication,visit_date"
    row = f"{patient_id},{name},{nhs_number},{dob},{postcode},{diagnosis},{test_result},{medication},{visit_date}"
    csv_content = f"{header}\n{row}"
    plaintext = csv_content.encode('utf-8')

    if not plaintext:
        print("  [ERROR] No data entered.")
        return

    # ── Assign a researcher ───────────────────────────────────
    print("\n  Data entered.")
    print("  Assign this dataset to a specific researcher.")
    print("  Only the assigned researcher will be able to access the controlled copy.")

    assigned_researcher = _pick_researcher()
    if assigned_researcher is None:
        print("  Entry cancelled — no researcher assigned.")
        return

    # ── Encrypt, pseudonymise, store, record assignment ───────────────────
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"manual_patient_data_{timestamp}.csv"
    print(f"\n  Encrypting '{filename}' with AES-256-GCM...")
    original_path, controlled_path = store_original_dataset(
        plaintext, filename, assigned_researcher
    )

    print(f"\n  [OK] Original stored    : {original_path}")
    print(f"  [OK] Controlled stored  : {controlled_path}")
    print(f"  [OK] Assigned researcher: {assigned_researcher}")
    print(f"  [OK] SHA-256 hashes saved")

    log_event(
        get_current_user(), get_current_role(), "UPLOAD",
        f"file={filename} | assigned_to={assigned_researcher} | method=manual",
    )
    print("  [OK] Audit log updated.")


def _clinician_retrieve() -> None:
    """Decrypt and display an original patient dataset (Clinician only)."""
    if not has_permission("retrieve_dataset"):
        print("  [RBAC] Access denied.")
        return

    datasets = list_original_datasets()
    print("\n  Available encrypted datasets:")
    chosen = _pick_file(datasets, "Select dataset to decrypt")
    if chosen is None:
        return

    try:
        plaintext = retrieve_original_dataset(chosen)
        print(f"\n  Decrypted content of '{chosen}':")
        print("  " + "-" * 54)
        print(plaintext.decode("utf-8", errors="replace"))
        print("  " + "-" * 54)
        log_event(get_current_user(), get_current_role(), "RETRIEVE", f"file={chosen}")
    except Exception as exc:
        print(f"  [ERROR] Decryption failed: {exc}")
        log_event(
            get_current_user(), get_current_role(), "RETRIEVE_FAILED",
            f"file={chosen} | error={exc}",
        )


def _clinician_list() -> None:
    """List datasets in the original zone, showing each dataset's assigned researcher."""
    if not has_permission("list_original"):
        print("  [RBAC] Access denied.")
        return
    datasets = list_original_datasets()
    print("\n  Stored encrypted datasets:")
    if not datasets:
        print("    (none)")
    for name in datasets:
        assigned = get_assigned_researcher(name) or "(unassigned)"
        print(f"    - {name}   → assigned to: {assigned}")


def _clinician_view_assignments() -> None:
    """Display the full dataset-to-researcher assignment map."""
    if not has_permission("list_original"):
        print("  [RBAC] Access denied.")
        return
    assignments = list_assignments()
    print("\n  Dataset-to-Researcher Assignments:")
    if not assignments:
        print("    (none)")
    for dataset, researcher in assignments.items():
        print(f"    {dataset:45s}  →  {researcher}")


# ── Researcher menu ───────────────────────────────────────────────────────────

def researcher_menu() -> None:
    """
    Main loop for the Researcher role.

    Available operations:
      [1] List available controlled datasets    (only assigned ones shown)
      [2] Decrypt and view an assigned dataset  (FEATURE 2 enforced here)
      [3] Create research findings              (FEATURE 1 — type or load .txt)
      [4] Sign a findings file                  (separate from creation)
      [5] List findings files
      [6] Read a findings file
      [0] Logout

    FEATURE 1: Options [3] and [4] are deliberately separated.
      [3] creates and saves the findings document (draft stage)
      [4] applies an RSA-PSS signature (formal sign-off stage)

    FEATURE 2: Option [2] enforces dataset-level assignment.
      If the current researcher is not assigned to a dataset, access is denied.
    """
    while True:
        _print_header("RESEARCHER PORTAL")
        print("  [1] List available controlled (pseudonymised) datasets")
        print("  [2] Decrypt and view an assigned dataset")
        print("  [3] Create research findings  (type inline or load .txt file)")
        print("  [4] Sign a findings file       (RSA-PSS digital signature)")
        print("  [5] List findings files")
        print("  [6] Read a findings file")
        print("  [0] Logout")

        choice = input("\nSelect option: ").strip()
        if choice == "1":
            _researcher_list()
        elif choice == "2":
            _researcher_decrypt()
        elif choice == "3":
            _researcher_create_findings()
        elif choice == "4":
            _researcher_sign_findings()
        elif choice == "5":
            _researcher_list_findings()
        elif choice == "6":
            _researcher_read_findings()
        elif choice == "0":
            log_event(get_current_user(), get_current_role(), "LOGOUT", "")
            logout()
            print("\n  Logged out successfully.")
            break
        else:
            print("  Invalid option.")


def _researcher_list() -> None:
    """List controlled datasets assigned to the current researcher only."""
    if not has_permission("list_controlled"):
        print("  [RBAC] Access denied.")
        return

    datasets     = list_controlled_datasets()
    current_user = get_current_user()
    my_datasets  = [d for d in datasets if get_assigned_researcher(d) == current_user]

    print(f"\n  Controlled datasets assigned to '{current_user}':")
    if not my_datasets:
        print("    (none — ask a Clinician to assign a dataset to you)")
    for name in my_datasets:
        print(f"    - {name}")


def _researcher_decrypt() -> None:
    """
    Decrypt a controlled dataset, enforcing dataset-level assignment.

    FEATURE 2 enforcement:
      retrieve_controlled_dataset() checks data/assignments.json before decrypting.
      If the current user is not the assigned researcher, PermissionError is raised,
      caught here, and logged to the audit trail.
    """
    if not has_permission("decrypt_controlled"):
        print("  [RBAC] Access denied.")
        return

    datasets     = list_controlled_datasets()
    current_user = get_current_user()
    my_datasets  = [d for d in datasets if get_assigned_researcher(d) == current_user]

    print(f"\n  Controlled datasets assigned to '{current_user}':")
    chosen = _pick_file(my_datasets, "Select dataset to decrypt")
    if chosen is None:
        return

    try:
        content = retrieve_controlled_dataset(chosen, current_user)
        print(f"\n  Decrypted controlled dataset '{chosen}':")
        print("  [All direct patient identifiers have been pseudonymised — GDPR compliant]")
        print("  " + "-" * 54)
        print(content.decode("utf-8", errors="replace"))
        print("  " + "-" * 54)
        log_event(
            get_current_user(), get_current_role(), "DECRYPT_CONTROLLED",
            f"file={chosen}",
        )

    except PermissionError as exc:
        # Assignment enforcement — another researcher's dataset
        print(f"\n  [ACCESS DENIED] {exc}")
        log_event(
            get_current_user(), get_current_role(), "ACCESS_DENIED",
            f"file={chosen} | reason=not_assigned_researcher",
        )
    except Exception as exc:
        print(f"  [ERROR] {exc}")


def _researcher_create_findings() -> None:
    """
    FEATURE 1 — Create a research findings document (two input methods).

    Option A: Type findings directly in the terminal.
      - Enter content line by line; type END on a blank line to finish.
      - Empty submissions are rejected.

    Option B: Load from a .txt file on disk.
      - Enter the path to a .txt file.
      - Validates: path exists, is a .txt file, is non-empty, is UTF-8 text.

    The findings are saved to data/findings/. Signing is done separately
    via option [4], keeping creation and formal sign-off as distinct steps.
    """
    if not has_permission("sign_findings"):
        print("  [RBAC] Access denied.")
        return

    print("\n  Create research findings — choose input method:")
    print("  [A] Type findings directly in the terminal")
    print("  [B] Load from a .txt file  (e.g. sample_data/findings_trial1.txt)")
    method = input("  Choice (A/B): ").strip().upper()

    # Select associated dataset
    my_datasets = [d for d in list_controlled_datasets() if get_assigned_researcher(d) == get_current_user()]
    if not my_datasets:
        print("  [ERROR] No assigned datasets found. Cannot create findings without an associated dataset.")
        return
    print("\n  Select the controlled dataset this findings is associated with:")
    chosen_dataset = _pick_file(my_datasets, "Select dataset")
    if chosen_dataset is None:
        return
    dataset_base = chosen_dataset.replace('.csv', '')  # Remove extension for filename

    content: bytes | None = None
    filename: str | None  = None

    # ── Option A: inline text entry ───────────────────────────────────────
    if method == "A":
        filename = input("\n  Save as filename (e.g. findings_trial1.txt): ").strip()
        if not filename:
            print("  [ERROR] No filename entered. Cancelled.")
            return
        if not filename.endswith(".txt"):
            filename += ".txt"
        filename = f"{get_current_user()}_{dataset_base}_{filename}"

        print("  Enter findings content. Type END on a new line to finish:")
        print("  " + "-" * 40)
        lines = []
        while True:
            line = input()
            if line.strip().upper() == "END":
                break
            lines.append(line)

        joined = "\n".join(lines).strip()
        if not joined:
            print("  [ERROR] No content entered. Nothing saved.")
            return

        content = joined.encode("utf-8")

    # ── Option B: load from .txt file ─────────────────────────────────────
    elif method == "B":
        filepath = input("\n  Path to .txt file: ").strip()

        if not filepath:
            print("  [ERROR] No path entered. Cancelled.")
            return
        if not os.path.isfile(filepath):
            print(f"  [ERROR] File not found: '{filepath}'")
            return
        if not filepath.lower().endswith(".txt"):
            print("  [ERROR] Only .txt files are accepted for findings.")
            return

        with open(filepath, "rb") as f:
            raw = f.read()

        if not raw:
            print("  [ERROR] File is empty.")
            return

        try:
            decoded = raw.decode("utf-8")
        except UnicodeDecodeError:
            print("  [ERROR] File is not valid UTF-8 text.")
            return

        if not decoded.strip():
            print("  [ERROR] File contains only whitespace.")
            return

        content  = raw
        filename = os.path.basename(filepath)
        filename = f"{get_current_user()}_{dataset_base}_{filename}"
        print(f"  Loaded {len(raw):,} bytes from '{filepath}'.")

    else:
        print("  Invalid choice. Please enter A or B.")
        return

    # ── Save findings ─────────────────────────────────────────────────────
    findings_path = store_findings(content, filename)
    display_name = filename[len(f"{get_current_user()}_{dataset_base}_"):]
    print(f"\n  [OK] Findings saved to: {findings_path}")
    print(f"       Hash stored for integrity checking.")
    print()
    print("  Use option [4] to apply a digital signature to this file.")

    log_event(
        get_current_user(), get_current_role(), "CREATE_FINDINGS",
        f"file={display_name} | dataset={chosen_dataset} | method={'inline' if method == 'A' else 'file'} | bytes={len(content)}",
    )


def _researcher_sign_findings() -> None:
    """
    FEATURE 1 — Sign a saved findings file with RSA-PSS (SHA-256).

    This is a separate step from findings creation, modelling the real-world
    distinction between drafting a document and formally signing it.

    Shows [signed] or [unsigned] status for each file. Re-signing is allowed
    (useful after content updates) with an explicit confirmation prompt.
    """
    if not has_permission("sign_findings"):
        print("  [RBAC] Access denied.")
        return

    all_findings = list_findings()
    current_user = get_current_user()
    my_findings = [f for f in all_findings if f.startswith(f"{current_user}_")]
    if not my_findings:
        print("\n  No findings files found. Use option [3] to create findings first.")
        return

    print("\n  Select your findings file to sign:")
    for i, name in enumerate(my_findings, 1):
        parts = name.split('_', 2)
        if len(parts) >= 3:
            _, dataset, fname = parts
        else:
            dataset, fname = 'unknown', name
        sig_exists = os.path.exists(os.path.join(FINDINGS_DIR, name + ".sig"))
        status = "[signed]  " if sig_exists else "[unsigned]"
        print(f"  [{i}] {fname}  {status} (dataset {dataset})")

    try:
        choice = int(input("\n  Select file (0 to cancel): "))
        if choice == 0:
            return
        chosen = my_findings[choice - 1]
        parts = chosen.split('_', 2)
        if len(parts) >= 3:
            _, _, display_name = parts
        else:
            display_name = chosen
    except (ValueError, IndexError):
        print("  Invalid selection.")
        return

    findings_path = os.path.join(FINDINGS_DIR, chosen)

    # Confirm re-signing if a signature already exists
    if os.path.exists(findings_path + ".sig"):
        confirm = input(f"  '{display_name}' is already signed. Re-sign? (y/n): ").strip().lower()
        if confirm != "y":
            print("  Signing cancelled.")
            return

    print(f"\n  Signing '{display_name}' with RSA-PSS (SHA-256, 2048-bit key)...")
    sig_path = sign_file(findings_path, "researcher")
    print(f"  [OK] Signature saved to: {sig_path}")
    print(f"       Signature size: {os.path.getsize(sig_path)} bytes")
    print(f"       The Auditor can verify this signature using option [1].")

    log_event(
        get_current_user(), get_current_role(), "SIGN_FINDINGS",
        f"file={display_name} | sig={sig_path}",
    )
    print("  [OK] Audit log updated.")


def _researcher_list_findings() -> None:
    """List all findings files, showing signed/unsigned status and association details."""
    if not has_permission("list_findings"):
        print("  [RBAC] Access denied.")
        return
    findings = list_findings()
    print("\n  All stored findings files (data/findings/):")
    if not findings:
        print("    (none — use option [3] to create findings)")
    for name in findings:
        parts = name.split('_', 2)
        if len(parts) >= 3:
            owner, dataset, fname = parts
        else:
            owner, dataset, fname = 'unknown', 'unknown', name
        sig_exists = os.path.exists(os.path.join(FINDINGS_DIR, name + ".sig"))
        status = "[signed]  " if sig_exists else "[unsigned]"
        print(f"    - {fname}  {status} (by {owner}, dataset {dataset})")


def _researcher_read_findings() -> None:
    """Read and display the content of a selected findings file."""
    if not has_permission("list_findings"):  # Assuming same permission
        print("  [RBAC] Access denied.")
        return

    findings = list_findings()
    if not findings:
        print("\n  No findings files found.")
        return

    print("\n  Select findings file to read:")
    for i, name in enumerate(findings, 1):
        parts = name.split('_', 2)
        if len(parts) >= 3:
            owner, dataset, fname = parts
        else:
            owner, dataset, fname = 'unknown', 'unknown', name
        sig_exists = os.path.exists(os.path.join(FINDINGS_DIR, name + ".sig"))
        status = "[signed]  " if sig_exists else "[unsigned]"
        print(f"  [{i}] {fname}  {status} (by {owner}, dataset {dataset})")

    try:
        choice = int(input("\n  Select file (0 to cancel): "))
        if choice == 0:
            return
        chosen = findings[choice - 1]
        parts = chosen.split('_', 2)
        if len(parts) >= 3:
            _, _, display_name = parts
        else:
            display_name = chosen
    except (ValueError, IndexError):
        print("  Invalid selection.")
        return

    findings_path = os.path.join(FINDINGS_DIR, chosen)
    try:
        with open(findings_path, 'r', encoding='utf-8') as f:
            content = f.read()
        print(f"\n  Content of '{display_name}':")
        print("  " + "-" * 50)
        print(content)
    except Exception as e:
        print(f"  [ERROR] Failed to read file: {e}")


# ── Auditor menu ──────────────────────────────────────────────────────────────

def auditor_menu() -> None:
    """
    Main loop for the Auditor role.

    Available operations:
      [1] Verify a digital signature
      [2] Check file integrity (SHA-256)
      [3] View audit log
      [4] Verify audit log integrity
      [5] List all stored files
      [6] View dataset-researcher assignments
      [7] Demonstrate RBAC access denial
      [0] Logout
    """
    while True:
        _print_header("AUDITOR PORTAL")
        print("  [1] Verify a digital signature")
        print("  [2] Check file integrity (SHA-256)")
        print("  [3] View audit log")
        print("  [4] Verify audit log integrity")
        print("  [5] List all stored files")
        print("  [6] View dataset-researcher assignments")
        print("  [7] Demonstrate RBAC access denial")
        print("  [0] Logout")

        choice = input("\nSelect option: ").strip()
        if choice == "1":
            _auditor_verify_sig()
        elif choice == "2":
            _auditor_check_integrity()
        elif choice == "3":
            _auditor_view_log()
        elif choice == "4":
            _auditor_verify_log()
        elif choice == "5":
            _auditor_list_all()
        elif choice == "6":
            _auditor_view_assignments()
        elif choice == "7":
            _demonstrate_rbac_denial()
        elif choice == "0":
            log_event(get_current_user(), get_current_role(), "LOGOUT", "")
            logout()
            print("\n  Logged out successfully.")
            break
        else:
            print("  Invalid option.")


def _auditor_verify_sig() -> None:
    """Verify RSA-PSS signature on a findings file."""
    if not has_permission("verify_signature"):
        print("  [RBAC] Access denied.")
        return

    findings = list_findings()
    print("\n  Select findings file to verify:")
    chosen = _pick_file(findings, "Select file")
    if chosen is None:
        return

    findings_path = os.path.join(FINDINGS_DIR, chosen)
    sig_path      = findings_path + ".sig"

    if not os.path.exists(sig_path):
        print(f"  [WARN] No .sig file found for '{chosen}'.")
        log_event(get_current_user(), get_current_role(), "VERIFY_SIG_MISSING", f"file={chosen}")
        return

    print("  Verifying RSA-PSS signature using researcher public key...")
    valid = verify_signature(findings_path, sig_path, "researcher")

    if valid:
        print("  [VALID]   Signature verified — file is authentic and unmodified.")
    else:
        print("  [INVALID] Signature verification FAILED — file may have been tampered.")

    log_event(
        get_current_user(), get_current_role(), "VERIFY_SIG",
        f"file={chosen} | result={'VALID' if valid else 'INVALID'}",
    )


def _auditor_check_integrity() -> None:
    """Recompute SHA-256 of a file and compare against stored companion hash."""
    if not has_permission("check_integrity"):
        print("  [RBAC] Access denied.")
        return

    print("\n  Select data zone:")
    print("  [1] Original datasets")
    print("  [2] Controlled datasets")
    print("  [3] Findings files")
    zone = input("  Zone: ").strip()

    zone_map = {
        "1": (list_original_datasets(),  ORIGINAL_DIR),
        "2": (list_controlled_datasets(), CONTROLLED_DIR),
        "3": (list_findings(),            FINDINGS_DIR),
    }
    if zone not in zone_map:
        print("  Invalid selection.")
        return

    file_list, directory = zone_map[zone]
    chosen = _pick_file(file_list, "Select file")
    if chosen is None:
        return

    file_path            = os.path.join(directory, chosen)
    match, stored, computed = crypto_verify_integrity(file_path)

    print(f"\n  File          : {chosen}")
    print(f"  Stored hash   : {stored}")
    print(f"  Computed hash : {computed}")

    if match:
        print("  [MATCH]    Integrity verified — no tampering detected.")
    else:
        print("  [MISMATCH] Integrity FAILED — file may have been altered!")

    log_event(
        get_current_user(), get_current_role(), "INTEGRITY_CHECK",
        f"file={chosen} | result={'MATCH' if match else 'MISMATCH'}",
    )


def _auditor_view_log() -> None:
    """Display the full audit log."""
    if not has_permission("view_audit_log"):
        print("  [RBAC] Access denied.")
        return
    print("\n  " + "=" * 54)
    print("  AUDIT LOG")
    print("  " + "=" * 54)
    print(read_log())
    print("  " + "=" * 54)
    log_event(get_current_user(), get_current_role(), "VIEW_LOG", "")


def _auditor_verify_log() -> None:
    """Verify the rolling SHA-256 hash of the audit log."""
    if not has_permission("view_audit_log"):
        print("  [RBAC] Access denied.")
        return
    match, stored, computed = verify_log_integrity()
    print(f"\n  Stored    : {stored}")
    print(f"  Computed  : {computed}")
    if match:
        print("  [MATCH]    Audit log integrity verified.")
    else:
        print("  [MISMATCH] Audit log may have been altered!")
    log_event(
        get_current_user(), get_current_role(), "VERIFY_LOG_INTEGRITY",
        f"result={'MATCH' if match else 'MISMATCH'}",
    )


def _auditor_list_all() -> None:
    """Inventory of all files across every storage zone."""
    if not has_permission("list_all_files"):
        print("  [RBAC] Access denied.")
        return
    all_files = list_all_stored_files()
    print("\n  === Full File Inventory ===")
    for zone, files in all_files.items():
        print(f"\n  [{zone.upper()}]")
        if not files:
            print("    (empty)")
        for name in files:
            print(f"    - {name}")


def _auditor_view_assignments() -> None:
    """Show the full dataset-to-researcher assignment map."""
    if not has_permission("list_all_files"):
        print("  [RBAC] Access denied.")
        return
    assignments = list_assignments()
    print("\n  Dataset-to-Researcher Assignments:")
    if not assignments:
        print("    (none recorded yet)")
    for dataset, researcher in assignments.items():
        print(f"    {dataset:45s}  →  {researcher}")
    log_event(
        get_current_user(), get_current_role(), "VIEW_ASSIGNMENTS",
        f"total={len(assignments)}",
    )


def _demonstrate_rbac_denial() -> None:
    """Show RBAC enforcement — forbidden actions for Auditor role. All denials are logged."""
    if not has_permission("view_audit_log"):
        print("  [RBAC] Access denied.")
        return

    print("\n  === RBAC Enforcement Demonstration ===")
    print(f"  Current role: {get_current_role()}\n")

    forbidden = [
        ("upload_dataset",     "clinician"),
        ("retrieve_dataset",   "clinician"),
        ("decrypt_controlled", "researcher"),
        ("sign_findings",      "researcher"),
    ]
    for action, required_role in forbidden:
        if has_permission(action):
            print(f"  [PERMITTED]   '{action}'")
        else:
            print(f"  [RBAC DENIED] '{action}'  — requires role '{required_role}'")
            log_event(
                get_current_user(), get_current_role(), "ACCESS_DENIED",
                f"attempted_action={action}",
            )

    print("\n  All denied actions logged to audit log.")
    print("  === End of Demonstration ===")
