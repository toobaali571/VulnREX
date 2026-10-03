"""
re_module.py
Reverse-engineering integration: works against a locally installed copy
of Ghidra (free, open-source, NSA-developed). Supports:

  - Opening the interactive Ghidra GUI (ghidraRun) for manual analysis.
  - Running Ghidra headless (analyzeHeadless) with a bundled post-script
    that auto-imports a binary, runs Ghidra's analyzers, and dumps a
    triage summary (functions, imports, strings) to JSON.
  - Lightweight static pre-triage that needs no Ghidra install at all
    (file type sniffing + printable-string extraction) so the analyst
    has something to look at immediately.

VulnREX does not ship or bundle Ghidra. It shells out to a Ghidra
install already present on the analyst's machine (or pointed to via
the GHIDRA_INSTALL_DIR environment variable / the GUI's Browse button),
exactly like launching it manually would.
"""

import json
import os
import re
import shutil
import subprocess
import tempfile
import platform

from vulnrex.utils import timestamp

PRINTABLE_RUN = re.compile(rb"[\x20-\x7e]{4,}")

SCRIPTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ghidra_scripts")
TRIAGE_SCRIPT = "vulnrex_triage.py"


class REError(Exception):
    pass


# ---------------------------------------------------------------------- #
# Locating a Ghidra install
# ---------------------------------------------------------------------- #
def find_ghidra_install():
    """
    Try to auto-detect a Ghidra installation directory (the folder
    containing ghidraRun / ghidraRun.bat and support/analyzeHeadless).
    Checks $GHIDRA_INSTALL_DIR first, then common install locations.
    Returns the install dir path, or None if not found.
    """
    env_dir = os.environ.get("GHIDRA_INSTALL_DIR")
    if env_dir and _looks_like_ghidra_home(env_dir):
        return env_dir

    system = platform.system()
    candidates = []
    if system == "Windows":
        candidates += [
            r"C:\ghidra",
            r"C:\Program Files\ghidra",
        ]
    elif system == "Darwin":
        candidates += [
            "/Applications/ghidra",
            os.path.expanduser("~/ghidra"),
        ]
    else:  # Linux / Kali (Ghidra is preinstalled at /opt/ghidra on Kali)
        candidates += [
            "/opt/ghidra",
            "/usr/share/ghidra",
            os.path.expanduser("~/ghidra"),
        ]

    for base in candidates:
        if _looks_like_ghidra_home(base):
            return base
        # installs are often unpacked into a versioned subfolder,
        # e.g. /opt/ghidra_11.1_PUBLIC
        parent = os.path.dirname(base)
        if os.path.isdir(parent):
            for name in os.listdir(parent):
                full = os.path.join(parent, name)
                if name.lower().startswith("ghidra") and _looks_like_ghidra_home(full):
                    return full
    return None


def _looks_like_ghidra_home(path: str) -> bool:
    if not path or not os.path.isdir(path):
        return False
    run_script = "ghidraRun.bat" if platform.system() == "Windows" else "ghidraRun"
    headless = os.path.join(path, "support",
                             "analyzeHeadless.bat" if platform.system() == "Windows"
                             else "analyzeHeadless")
    return os.path.isfile(os.path.join(path, run_script)) and os.path.isfile(headless)


def _ghidra_run_path(ghidra_home: str) -> str:
    name = "ghidraRun.bat" if platform.system() == "Windows" else "ghidraRun"
    return os.path.join(ghidra_home, name)


def _analyze_headless_path(ghidra_home: str) -> str:
    name = "analyzeHeadless.bat" if platform.system() == "Windows" else "analyzeHeadless"
    return os.path.join(ghidra_home, "support", name)


# ---------------------------------------------------------------------- #
# Launching Ghidra
# ---------------------------------------------------------------------- #
def launch_ghidra_gui(ghidra_home: str, log=None):
    """
    Launch the interactive Ghidra GUI (ghidraRun) as a detached process.
    Ghidra's GUI doesn't accept a "file to open" argument the way IDA
    does; the analyst imports the binary manually via File > Import
    once the GUI is up.
    """
    run_path = _ghidra_run_path(ghidra_home)
    if not os.path.isfile(run_path):
        raise REError(f"ghidraRun not found at: {run_path}")

    if log:
        log(f"[{timestamp()}] Launching Ghidra GUI: {run_path}")
        log("Use File > Import File... inside Ghidra to load your target binary.")

    kwargs = {}
    if platform.system() == "Windows":
        kwargs["creationflags"] = subprocess.DETACHED_PROCESS
    subprocess.Popen([run_path], close_fds=True, **kwargs)


def run_headless_analysis(ghidra_home: str, binary_path: str, log=None, timeout: int = 600):
    """
    Runs Ghidra headless against binary_path using analyzeHeadless plus
    the bundled vulnrex_triage.py post-script, which dumps functions,
    imports, and strings to a temp JSON file that we then parse and
    return as a dict. The scratch Ghidra project is deleted afterward
    (-deleteProject).
    """
    headless = _analyze_headless_path(ghidra_home)
    if not os.path.isfile(headless):
        raise REError(f"analyzeHeadless not found at: {headless}")
    if not os.path.isfile(binary_path):
        raise REError(f"Target binary not found: {binary_path}")
    if not os.path.isfile(os.path.join(SCRIPTS_DIR, TRIAGE_SCRIPT)):
        raise REError(f"Bundled script missing: {TRIAGE_SCRIPT}")

    with tempfile.TemporaryDirectory(prefix="vulnrex_ghidra_") as tmp_dir:
        output_json = os.path.join(tmp_dir, "triage.json")
        project_name = "vulnrex_tmp"

        cmd = [
            headless, tmp_dir, project_name,
            "-import", binary_path,
            "-scriptPath", SCRIPTS_DIR,
            "-postScript", TRIAGE_SCRIPT, output_json,
            "-deleteProject",
        ]

        if log:
            log(f"[{timestamp()}] Running Ghidra headless analysis on {binary_path} ...")
            log("(This may take a minute or two on first run.)")

        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout
            )
        except subprocess.TimeoutExpired:
            raise REError(f"Ghidra headless analysis timed out after {timeout}s")

        if log:
            for line in proc.stdout.splitlines()[-40:]:
                log(line)

        if proc.returncode != 0:
            raise REError(
                f"analyzeHeadless exited with code {proc.returncode}. "
                f"See log output above / stderr for details."
            )

        if not os.path.isfile(output_json):
            raise REError(
                "Ghidra ran but did not produce a triage output file. "
                "Check that the target is a supported binary format."
            )

        with open(output_json, "r") as fh:
            data = json.load(fh)

        if log:
            log(f"[{timestamp()}] Headless analysis complete: "
                f"{len(data.get('functions', []))} function(s), "
                f"{len(data.get('imports', []))} import(s), "
                f"{len(data.get('strings', []))} string(s).")

        data["path"] = binary_path
        return data


# ---------------------------------------------------------------------- #
# Zero-dependency static pre-triage (no Ghidra required)
# ---------------------------------------------------------------------- #
def quick_triage(binary_path: str, max_strings: int = 40):
    """
    Cheap static pre-analysis so the analyst has something to look at
    before/while Ghidra runs: file size, guessed format, a sample of
    printable strings, and (best-effort) ELF import names via `nm -D`.
    Does NOT execute the binary and does NOT require Ghidra.
    """
    if not os.path.isfile(binary_path):
        raise REError(f"File not found: {binary_path}")

    with open(binary_path, "rb") as fh:
        data = fh.read()

    file_size = len(data)
    file_format = _guess_format(data)
    strings = _extract_strings(data, limit=max_strings)
    imports = _elf_imports(binary_path) if file_format == "ELF" else []

    return {
        "path": binary_path,
        "size_bytes": file_size,
        "format": file_format,
        "sample_strings": strings,
        "imports": imports,
    }


def _guess_format(data: bytes) -> str:
    if data[:4] == b"\x7fELF":
        return "ELF"
    if data[:2] == b"MZ":
        return "PE (Windows)"
    if data[:4] in (b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe",
                     b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe"):
        return "Mach-O"
    return "Unknown"


def _extract_strings(data: bytes, limit: int = 40):
    results = []
    for match in PRINTABLE_RUN.finditer(data):
        s = match.group().decode("ascii", errors="ignore")
        if len(s) >= 4:
            results.append(s)
        if len(results) >= limit:
            break
    return results


def _elf_imports(binary_path: str):
    """Best-effort import listing via `nm -D` if available; otherwise empty."""
    if shutil.which("nm") is None:
        return []
    try:
        out = subprocess.run(
            ["nm", "-D", binary_path], capture_output=True, text=True, timeout=15
        )
        names = []
        for line in out.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 3 and parts[1] in ("U", "T", "W"):
                names.append(parts[-1])
        return sorted(set(names))[:100]
    except Exception:
        return []
