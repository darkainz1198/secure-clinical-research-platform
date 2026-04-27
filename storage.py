"""
storage.py — Dataset Storage, Retrieval, and Pseudonymisation
ClineaCrypt | WM9PC-15 Applied Cryptography

Handles all file-based storage operations:
  - Encrypting and storing original patient datasets (Clinician zone)
  - Generating pseudonymised copies and storing them (Researcher zone)
  - Storing and retrieving researcher findings files
  - Providing file listings for each zone

Data zone layout (enforced by directory separation + separate AES keys):
  data/original/    ← AES-encrypted full patient datasets (Clinician key)
  data/controlled/  ← AES-encrypted pseudonymised datasets (Controlled key)
  data/findings/    ← AES-encrypted researcher findings + RSA .sig files
  data/hashes/      ← SHA-256 companion .hash files for integrity checking

Pseudonymisation design (GDPR compliance):
  Article 4(5) GDPR defines pseudonymisation as replacing identifying
  information with tokens such that re-identification requires additional
  information held separately. This module implements that principle:

  Identifiers removed (replaced with ANON_XXXX tokens):
    patient_id, name, nhs_number, dob, postcode, address, phone, email,
    surname, first_name, last_name, telephone, and common variants.

  Clinical values retained (needed for research):
    diagnosis, test_result, medication, visit_date, and all other columns
    not matching an identifier pattern.

  This satisfies:
    - GDPR Article 5(1)(c): data minimisation — only what is needed
    - GDPR Article 25: data protection by design and by default
    - GDPR Article 9: appropriate safeguards for health data processing
"""

import os
import csv
import io

from crypto_utils import (
    encrypt_data,
    decrypt_data,
    get_original_key,
    get_controlled_key,
    get_findings_key,
    hash_file,
    save_hash,
    ORIGINAL_DIR,
    CONTROLLED_DIR,
    FINDINGS_DIR,
    HASHES_DIR,
)

# ── Identifier field names to pseudonymise ────────────────────────────────────
# Matched case-insensitively against CSV column headers (spaces → underscores).
# Any column whose normalised name appears in this set will have its values
# replaced with opaque ANON_XXXX tokens and its header prefixed with REDACTED_.
IDENTIFIER_FIELDS = {
    "patient_id", "patientid",
    "name", "patient_name", "patientname", "surname", "firstname",
    "first_name", "last_name", "lastname",
    "nhs_number", "nhsnumber", "nhs",
    "dob", "date_of_birth", "dateofbirth",
    "postcode", "postal_code", "postalcode",
    "address",
    "phone", "telephone", "email",
}


def _ensure_dirs() -> None:
    """Create all required data directories if they do not already exist."""
    for directory in [ORIGINAL_DIR, CONTROLLED_DIR, FINDINGS_DIR, HASHES_DIR]:
        os.makedirs(directory, exist_ok=True)


# ── Pseudonymisation ──────────────────────────────────────────────────────────

def _is_identifier_field(header: str) -> bool:
    """
    Return True if a CSV column header matches a known identifier field name.
    Normalisation: strip whitespace, lowercase, replace spaces with underscores.
    This handles headers like 'NHS Number', 'nhs_number', 'NHSNumber' equally.
    """
    return header.strip().lower().replace(" ", "_") in IDENTIFIER_FIELDS


def _pseudonymise_token(row_index: int) -> str:
    """
    Return a zero-padded opaque token for a given row, e.g. 'ANON_0001'.
    The token is deterministic within a file but carries no identifying
    information and cannot be reversed without the original data.
    """
    return f"ANON_{row_index:04d}"


def pseudonymise_csv(csv_bytes: bytes) -> bytes:
    """
    Strip direct identifiers from a CSV dataset and return pseudonymised bytes.

    Transformation applied to each column:
      - Identifier column header → REDACTED_<original_header>
      - Each cell in an identifier column → ANON_XXXX (row-indexed token)
      - All other columns (diagnosis, test results, etc.) → copied unchanged

    Example input row:
      P001, John Smith, 123-456-7890, 1975-04-12, CV1 2AA, Type 2 Diabetes, ...
    Example output row:
      Type 2 Diabetes, ..., ANON_0001, ANON_0001, ANON_0001, ANON_0001, ANON_0001

    The controlled (pseudonymised) CSV is what gets encrypted and stored in
    data/controlled/ for researcher access.
    """
    reader = csv.DictReader(io.StringIO(csv_bytes.decode("utf-8")))
    if reader.fieldnames is None:
        return csv_bytes  # Empty or headerless file — return as-is

    original_headers = list(reader.fieldnames)
    rows = list(reader)

    # Partition columns into identifier and safe sets
    identifier_cols = [h for h in original_headers if _is_identifier_field(h)]
    safe_cols       = [h for h in original_headers if not _is_identifier_field(h)]

    # Build output: safe columns first, then renamed (REDACTED_) identifier columns
    new_headers = safe_cols + [f"REDACTED_{h}" for h in identifier_cols]

    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=new_headers)
    writer.writeheader()

    for i, row in enumerate(rows):
        new_row = {}
        for col in safe_cols:
            new_row[col] = row[col]                          # Keep clinical values
        for col in identifier_cols:
            new_row[f"REDACTED_{col}"] = _pseudonymise_token(i + 1)  # Replace identifier
        writer.writerow(new_row)

    return output.getvalue().encode("utf-8")


def pseudonymise_text(text_bytes: bytes) -> bytes:
    """
    Strip identifier-related content from a plain text file (non-CSV fallback).

    Any line whose lowercase content contains an identifier keyword is replaced
    with the placeholder '[IDENTIFIER REDACTED]'. Lines without identifier
    keywords are preserved verbatim.

    This is a conservative approach: it may over-redact (e.g. a clinical note
    mentioning "patient name unknown"), but that is preferable to under-redacting
    real identifying information.
    """
    lines   = text_bytes.decode("utf-8").splitlines()
    cleaned = []
    for line in lines:
        lower = line.lower()
        if any(field in lower for field in IDENTIFIER_FIELDS):
            cleaned.append("[IDENTIFIER REDACTED]")
        else:
            cleaned.append(line)
    return "\n".join(cleaned).encode("utf-8")


def pseudonymise(content: bytes, filename: str) -> bytes:
    """
    Dispatch to the appropriate pseudonymisation function based on file type.
    CSV files use column-aware pseudonymisation; all other files use line-based.
    """
    if filename.lower().endswith(".csv"):
        return pseudonymise_csv(content)
    return pseudonymise_text(content)


# ── Clinician: upload original dataset ───────────────────────────────────────

def store_original_dataset(plaintext: bytes, filename: str, assigned_researcher: str) -> tuple[str, str]:
    """
    Encrypt and store a patient dataset, then generate and store its
    pseudonymised counterpart.

    Five operations in sequence:
      1. Encrypt with original AES key  → write to data/original/
      2. SHA-256 hash the encrypted file → save companion .hash
      3. Pseudonymise plaintext → encrypt with controlled key → write to data/controlled/
      4. SHA-256 hash the controlled file → save companion .hash
      5. Record dataset→researcher assignment in data/assignments.json

    Parameters:
      plaintext            Raw bytes of the patient dataset
      filename             Original filename (used to derive .enc basename)
      assigned_researcher  Username of the sole researcher authorised for this dataset

    The two encrypted files share the same base filename (.enc extension) but
    live in separate directories and are protected by different AES keys.
    Their hash files are namespaced by parent directory to prevent collisions
    (see crypto_utils._hash_key_for).

    Returns (original_path, controlled_path).
    """
    _ensure_dirs()

    # Build the .enc filename (strip original extension, add .enc)
    base         = os.path.splitext(filename)[0]
    enc_filename = base + ".enc"

    # ── 1. Encrypt original ────────────────────────────────────────────────
    original_key      = get_original_key()
    encrypted_original = encrypt_data(plaintext, original_key)
    original_path      = os.path.join(ORIGINAL_DIR, enc_filename)
    with open(original_path, "wb") as f:
        f.write(encrypted_original)

    # ── 2. Hash original ───────────────────────────────────────────────────
    # Hash is computed AFTER the write so it reflects the on-disk file exactly.
    save_hash(original_path, hash_file(original_path))

    # ── 3. Pseudonymise and encrypt controlled copy ────────────────────────
    pseudo_bytes       = pseudonymise(plaintext, filename)
    controlled_key     = get_controlled_key()
    encrypted_controlled = encrypt_data(pseudo_bytes, controlled_key)
    controlled_path    = os.path.join(CONTROLLED_DIR, enc_filename)
    with open(controlled_path, "wb") as f:
        f.write(encrypted_controlled)

    # ── 4. Hash controlled ─────────────────────────────────────────────────
    save_hash(controlled_path, hash_file(controlled_path))

    # ── 5. Record researcher assignment ───────────────────────────────────
    # Store enc_filename → assigned_researcher mapping so that access control
    # in retrieve_controlled_dataset() can enforce dataset-level restrictions.
    from assignments import assign_researcher
    assign_researcher(enc_filename, assigned_researcher)

    return original_path, controlled_path


# ── Clinician: retrieve original dataset ─────────────────────────────────────

def retrieve_original_dataset(enc_filename: str) -> bytes:
    """
    Decrypt and return the plaintext of an original patient dataset.

    Only callable during a Clinician session — Researcher and Auditor menus
    do not expose this function, and their roles do not have the
    'retrieve_dataset' permission in auth.ROLE_PERMISSIONS.
    The original AES key is loaded here; it is never passed to researcher code.
    """
    path = os.path.join(ORIGINAL_DIR, enc_filename)
    if not os.path.exists(path):
        raise FileNotFoundError(f"Original dataset not found: {enc_filename}")
    with open(path, "rb") as f:
        blob = f.read()
    return decrypt_data(blob, get_original_key())


# ── Researcher: access controlled dataset ────────────────────────────────────

def retrieve_controlled_dataset(enc_filename: str, researcher_username: str) -> bytes:
    """
    Decrypt and return the plaintext of a pseudonymised (controlled) dataset.

    Enforces dataset-level access control on top of role-level RBAC:
      - Looks up the assignment for enc_filename in data/assignments.json
      - Raises PermissionError if researcher_username is not the assigned user
      - Only proceeds to decryption if the assignment matches

    This means that even two accounts with the researcher role cannot
    cross-access each other's datasets. Each dataset is scoped to exactly
    one researcher as chosen by the Clinician during upload.

    Uses the controlled AES key exclusively — the original key is never
    loaded or available in this function.
    """
    from assignments import is_assigned, get_assigned_researcher
    # ── Assignment check ───────────────────────────────────────────────────
    if not is_assigned(enc_filename, researcher_username):
        assigned_to = get_assigned_researcher(enc_filename)
        if assigned_to is None:
            raise PermissionError(
                f"[ASSIGNMENT] Dataset '{enc_filename}' has no researcher assignment."
            )
        raise PermissionError(
            f"[ASSIGNMENT] Access denied: '{enc_filename}' is assigned to "
            f"'{assigned_to}', not '{researcher_username}'."
        )

    path = os.path.join(CONTROLLED_DIR, enc_filename)
    if not os.path.exists(path):
        raise FileNotFoundError(f"Controlled dataset not found: {enc_filename}")
    with open(path, "rb") as f:
        blob = f.read()
    return decrypt_data(blob, get_controlled_key())


# ── Researcher: store findings ────────────────────────────────────────────────

def store_findings(content: bytes, filename: str) -> str:
    """
    Encrypt and store a researcher's findings document to data/findings/ and save its hash.

    Findings are encrypted with AES-256-GCM using the findings key to ensure
    confidentiality. A SHA-256 companion hash is saved so that the auditor can
    later verify the findings have not been altered.

    Returns the full path to the stored findings file.
    """
    _ensure_dirs()
    findings_path = os.path.join(FINDINGS_DIR, filename)
    
    # Encrypt the findings content
    findings_key = get_findings_key()
    encrypted_content = encrypt_data(content, findings_key)
    
    with open(findings_path, "wb") as f:
        f.write(encrypted_content)
    # Save hash immediately after write, before any other operation
    save_hash(findings_path, hash_file(findings_path))
    return findings_path


def retrieve_findings(filename: str) -> bytes:
    """
    Decrypt and return the plaintext of a researcher's findings document.

    Only callable during a Researcher session — the findings AES key is only
    accessible to researchers. The findings are decrypted using the findings
    key that was used for encryption.
    """
    path = os.path.join(FINDINGS_DIR, filename)
    if not os.path.exists(path):
        raise FileNotFoundError(f"Findings file not found: {filename}")
    with open(path, "rb") as f:
        blob = f.read()
    return decrypt_data(blob, get_findings_key())


# ── File listing utilities ────────────────────────────────────────────────────

def list_files(directory: str, extension: str = "") -> list[str]:
    """
    Return a sorted list of filenames in directory, optionally filtered by extension.
    Returns an empty list if the directory does not exist.
    """
    if not os.path.exists(directory):
        return []
    return sorted([
        f for f in os.listdir(directory)
        if os.path.isfile(os.path.join(directory, f))
        and f.endswith(extension)
    ])


def list_original_datasets() -> list[str]:
    """Return filenames of all encrypted original datasets."""
    return list_files(ORIGINAL_DIR, ".enc")


def list_controlled_datasets() -> list[str]:
    """Return filenames of all encrypted controlled (pseudonymised) datasets."""
    return list_files(CONTROLLED_DIR, ".enc")


def list_findings() -> list[str]:
    """Return filenames of findings documents, excluding .sig companion files."""
    return [f for f in list_files(FINDINGS_DIR) if not f.endswith(".sig")]


def list_all_stored_files() -> dict[str, list[str]]:
    """
    Return all stored files grouped by zone.
    Used by the Auditor's 'list all files' menu option to provide a full
    inventory of the system's data holdings.
    """
    return {
        "original":   list_original_datasets(),
        "controlled": list_controlled_datasets(),
        "findings":   list_findings(),
        "hashes":     list_files(HASHES_DIR),
    }
