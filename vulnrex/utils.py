"""
utils.py
Helper functions for VulnREX: CVE extraction, risk scoring, and
misc formatting helpers shared across the GUI, scanner, and report modules.
"""

import re
import json
import os
from datetime import datetime

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

# Keyword -> risk weight, used when NSE scripts don't expose a CVSS score
# directly (many `vuln` category scripts print State: VULNERABLE plus prose).
SEVERITY_KEYWORDS = {
    "critical": 4,
    "remote code execution": 4,
    "rce": 4,
    "authentication bypass": 4,
    "high": 3,
    "privilege escalation": 3,
    "sql injection": 3,
    "medium": 2,
    "denial of service": 2,
    "dos": 2,
    "information disclosure": 2,
    "low": 1,
    "misconfiguration": 1,
}

RISK_LABELS = {4: "Critical", 3: "High", 2: "Medium", 1: "Low", 0: "Informational"}


def extract_cves(text: str):
    """Return a sorted list of unique CVE IDs found in a block of NSE output."""
    if not text:
        return []
    found = {m.upper() for m in CVE_PATTERN.findall(text)}
    return sorted(found)


def score_from_cvss(cvss: float) -> int:
    """Map a numeric CVSS score (0-10) to VulnREX's 0-4 risk scale."""
    if cvss is None:
        return 0
    if cvss >= 9.0:
        return 4
    if cvss >= 7.0:
        return 3
    if cvss >= 4.0:
        return 2
    if cvss > 0.0:
        return 1
    return 0


def score_from_text(text: str) -> int:
    """Fallback keyword-based scoring for NSE scripts that don't emit CVSS."""
    if not text:
        return 0
    lowered = text.lower()
    best = 0
    for keyword, weight in SEVERITY_KEYWORDS.items():
        if keyword in lowered:
            best = max(best, weight)
    return best


def classify_risk(cvss: float = None, text: str = "") -> str:
    """
    Combine CVSS (if the script provided one) and keyword scoring, then
    return a human-readable risk label: Critical / High / Medium / Low / Informational.
    """
    score = score_from_cvss(cvss) if cvss is not None else 0
    score = max(score, score_from_text(text))
    return RISK_LABELS[score]


def risk_rank(label: str) -> int:
    """Inverse lookup used for sorting findings by severity."""
    for rank, name in RISK_LABELS.items():
        if name == label:
            return rank
    return 0


def timestamp() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def ensure_dir(path: str):
    os.makedirs(path, exist_ok=True)
    return path


def save_json(data, path: str):
    ensure_dir(os.path.dirname(path) or ".")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, default=str)


def load_json(path: str, default=None):
    if not os.path.exists(path):
        return default if default is not None else {}
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def is_valid_target(target: str) -> bool:
    """
    Very light sanity check on the target field: rejects obviously empty
    or shell-metacharacter-laden input before it ever reaches python-nmap.
    Not a substitute for authorization -- see README.
    """
    if not target or not target.strip():
        return False
    banned = [";", "|", "&", "$", "`", "\n", "\r"]
    return not any(ch in target for ch in banned)
