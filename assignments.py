"""
assignments.py — Dataset-to-Researcher Assignment Management
ClineaCrypt | WM9PC-15 Applied Cryptography

This module implements researcher assignment for controlled datasets.

When a Clinician uploads a patient dataset, they must explicitly assign
one specific researcher account to the resulting controlled (pseudonymised)
copy. Only that assigned researcher can decrypt and access the dataset.
Any other researcher account is denied at runtime, regardless of role.

How it works:
  - Assignments are stored in data/assignments.json as a flat key-value map:
      { "dataset_filename.enc": "bob_researcher", ... }
  - The key is the .enc filename (same basename in both original/ and controlled/)
  - The value is the username of the assigned researcher

  - When a researcher attempts to decrypt a controlled dataset, the system
    calls is_assigned() to check whether their username matches the stored
    assignment before allowing decryption.

  - If the check fails, the system denies access and logs an ACCESS_DENIED
    event to the audit log.

GDPR relevance:
  This enforces purpose limitation (Article 5(1)(b)) and access minimisation:
  even within the researcher role, each individual only accesses the specific
  dataset(s) they have been authorised for by the data controller (Clinician).
  This models a real-world data sharing agreement at the system level.
"""

import json
import os

BASE_DIR         = os.path.dirname(os.path.abspath(__file__))
ASSIGNMENTS_FILE = os.path.join(BASE_DIR, "data", "assignments.json")


def _load_assignments() -> dict[str, str]:
    """
    Load the assignments store from disk.
    Returns an empty dict if the file does not exist yet.
    """
    if not os.path.exists(ASSIGNMENTS_FILE):
        return {}
    with open(ASSIGNMENTS_FILE, "r") as f:
        return json.load(f)


def _save_assignments(assignments: dict[str, str]) -> None:
    """Persist the assignments dict to assignments.json."""
    os.makedirs(os.path.dirname(ASSIGNMENTS_FILE), exist_ok=True)
    with open(ASSIGNMENTS_FILE, "w") as f:
        json.dump(assignments, f, indent=2)


def assign_researcher(enc_filename: str, researcher_username: str) -> None:
    """
    Record that researcher_username is the sole authorised accessor for
    the controlled dataset identified by enc_filename.

    If an assignment already exists for this file, it is overwritten —
    the Clinician can re-assign a dataset (e.g. if the researcher changes).

    Parameters:
      enc_filename         The .enc filename, e.g. 'patient_dataset_trial1.enc'
      researcher_username  The username of the assigned researcher account
    """
    assignments = _load_assignments()
    assignments[enc_filename] = researcher_username
    _save_assignments(assignments)


def get_assigned_researcher(enc_filename: str) -> str | None:
    """
    Return the username assigned to enc_filename, or None if no assignment exists.
    """
    assignments = _load_assignments()
    return assignments.get(enc_filename)


def is_assigned(enc_filename: str, researcher_username: str) -> bool:
    """
    Return True if researcher_username is the assigned researcher for enc_filename.

    Called before every controlled dataset decryption to enforce
    dataset-level access control on top of role-level RBAC.
    """
    assigned = get_assigned_researcher(enc_filename)
    return assigned == researcher_username


def list_assignments() -> dict[str, str]:
    """
    Return the full assignments map { enc_filename: researcher_username }.
    Used by the Auditor's file listing and the Clinician's upload confirmation.
    """
    return _load_assignments()


def get_researcher_usernames() -> list[str]:
    """
    Return a sorted list of all researcher usernames from users.json.
    Used by the Clinician upload flow to present a choice of who to assign.

    Reads users.json directly rather than importing from auth.py to avoid
    circular imports (auth imports nothing from here).
    """
    users_file = os.path.join(BASE_DIR, "data", "users.json")
    if not os.path.exists(users_file):
        return []
    with open(users_file, "r") as f:
        users = json.load(f)
    # Return only accounts with role == "researcher"
    return sorted([u for u, data in users.items() if data.get("role") == "researcher"])
