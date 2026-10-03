# VulnREX — Vulnerability Assessment & Reverse Engineering Toolkit

A desktop application (Python + Tkinter) that combines **network
vulnerability assessment** (Nmap + NSE) with **binary analysis**
(Ghidra integration) in a single interface, as described in the
semester project proposal.

> ⚠️ **Authorized use only.** Only scan hosts/networks you own or have
> explicit written permission to test. Unauthorized scanning may be
> illegal under computer-misuse laws in your jurisdiction (e.g. CFAA
> in the US). This tool is intended for coursework in a lab/CTF/own-
> infrastructure setting.

## Features

| Module | What it does |
|---|---|
| **Scan** | Host discovery, port/service/version detection, OS fingerprinting via `nmap -sV -O` |
| **Vulnerability Assessment** | Runs NSE `vuln` category scripts, extracts CVE IDs, classifies each finding as Critical/High/Medium/Low/Informational |
| **Findings** | Sortable, color-coded table of results with full script output per finding |
| **Reverse Engineering** | Auto-detects a local Ghidra install; runs quick static triage (file format, strings, ELF imports) without executing the binary; opens the Ghidra GUI for manual analysis; or runs Ghidra **headless** to auto-import, auto-analyze, and dump a function/import/string summary |
| **Reports** | One-click PDF report (via ReportLab) combining scan + RE findings |
| **History** | Every scan is saved locally as JSON and reloadable from the History tab |

## Requirements

- **OS:** Kali Linux (or any Linux/macOS/Windows with `nmap` installed)
- **Python:** 3.9+
- **Nmap:** must be installed and on `PATH` (`sudo apt install nmap`)
- **Ghidra:** free & open source, from https://ghidra-sre.org (Kali
  ships it preinstalled at `/opt/ghidra`). Requires a JDK 17+ runtime.
  VulnREX auto-detects common install locations, or you can set the
  `GHIDRA_INSTALL_DIR` environment variable / use the Browse button
  in the Reverse Engineering tab.

## Installation

```bash
git clone <this-repo>          # or unzip the provided archive
cd VulnREX
python3 -m venv venv
source venv/bin/activate       # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

## Running

```bash
python -m vulnrex.main
```

## Project layout

```
VulnREX/
├── requirements.txt
├── README.md
└── vulnrex/
    ├── __init__.py
    ├── main.py                    # Tkinter GUI (entry point)
    ├── scanner.py                  # python-nmap wrapper: discovery + NSE vuln scan
    ├── re_module.py                 # Ghidra launcher/headless runner + static binary triage
    ├── report_generator.py          # ReportLab PDF report builder
    ├── utils.py                     # CVE extraction, risk scoring, JSON helpers
    └── ghidra_scripts/
        └── vulnrex_triage.py         # Ghidra headless post-script (Jython) —
                                       # dumps functions/imports/strings to JSON
```

Scan history is stored at `~/.vulnrex/history/` and exported PDF
reports default to `~/.vulnrex/reports/`.

## Reverse Engineering workflow

Three options, from lightest to heaviest:

1. **Static Triage** (no Ghidra needed) — instant file-format
   detection, printable-string extraction, and best-effort ELF import
   listing via `nm -D`. Good for a first look while Ghidra loads.
2. **Open Ghidra GUI** — launches `ghidraRun`; import the binary
   manually via *File > Import* for full interactive disassembly and
   decompilation.
3. **Run Ghidra Headless Analysis** — calls `support/analyzeHeadless`
   with the bundled `vulnrex_triage.py` post-script, which auto-runs
   Ghidra's analyzers and exports a JSON summary (functions, imported
   symbols, defined strings) that VulnREX reads back into the GUI and
   PDF report. The scratch Ghidra project is deleted automatically
   afterward. This can take a minute or two on first run per binary.

## How risk is scored

Nmap's `vuln` scripts don't always emit a CVSS score, so VulnREX
combines two signals:

1. **CVSS number**, when a script provides one (mapped to Critical
   ≥9.0, High ≥7.0, Medium ≥4.0, Low >0).
2. **Keyword scoring** on the script's textual output (e.g. "remote
   code execution", "authentication bypass" → Critical; "denial of
   service" → Medium), used as a fallback/floor.

The higher of the two determines the final label.

## Extending

- Swap/extend NSE script selection in `scanner.py`
  (`NmapScanner.VULN_ARGS`).
- Add a CVE-database lookup (e.g. NVD API) in `utils.py` to enrich
  `extract_cves()` output with descriptions/CVSS vectors — listed as
  a future enhancement in the original proposal.
- Extend `ghidra_scripts/vulnrex_triage.py` to also dump decompiled
  C for flagged functions (Ghidra's `DecompInterface`), or add
  additional Ghidra post-scripts for deeper automated analysis.

## Disclaimer

This is an educational toolkit built for a university Vulnerability
Assessment & Reverse Engineering course. It orchestrates existing,
industry-standard tools (Nmap, Ghidra) — it does not perform
exploitation and does not include any exploit payloads.
