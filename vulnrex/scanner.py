"""
scanner.py
Wraps python-nmap to perform host discovery, port/service/version/OS
detection, and NSE vulnerability scanning. Designed to run scans in a
background thread and report progress back to the GUI via a callback.

IMPORTANT: Only scan hosts/networks you own or are explicitly authorized
to test. Unauthorized scanning may be illegal in your jurisdiction.
"""

import shutil
import subprocess
from vulnrex.utils import extract_cves, classify_risk, timestamp

try:
    import nmap  # python-nmap
except ImportError:  # allow the module to be imported for GUI/report testing
    nmap = None


class ScannerError(Exception):
    pass


class NmapScanner:
    """
    Thin, GUI-friendly wrapper around python-nmap's PortScanner.

    Usage:
        scanner = NmapScanner()
        result = scanner.run_full_scan("192.168.1.10", log=print)
    """

    # -sV: version detection, -O: OS detection, -T4: timing template
    # (intentionally no --open: hosts that are up but have zero open
    # ports should still be reported, not silently dropped)
    DISCOVERY_ARGS = "-sV -O -T4"

    # NSE 'vuln' category runs every safe vulnerability-detection script
    VULN_ARGS = "-sV --script vuln"

    def __init__(self):
        if nmap is None:
            raise ScannerError(
                "python-nmap is not installed. Run: pip install python-nmap"
            )
        if shutil.which("nmap") is None:
            raise ScannerError(
                "The 'nmap' binary was not found on PATH. Install nmap "
                "(e.g. 'sudo apt install nmap') before scanning."
            )
        self.pm = nmap.PortScanner()

    # ------------------------------------------------------------------ #
    # Discovery / enumeration
    # ------------------------------------------------------------------ #
    def discover(self, target: str, log=None):
        """Host discovery + port/service/version/OS detection."""
        if log:
            log(f"[{timestamp()}] Starting discovery scan on {target} ...")
        self.pm.scan(hosts=target, arguments=self.DISCOVERY_ARGS)
        return self._parse_discovery(target, log)

    def _parse_discovery(self, target: str, log=None):
        hosts_out = []
        for host in self.pm.all_hosts():
            info = {
                "host": host,
                "state": self.pm[host].state(),
                "os_guesses": [],
                "ports": [],
            }
            if "osmatch" in self.pm[host]:
                for osm in self.pm[host]["osmatch"][:3]:
                    info["os_guesses"].append(
                        {"name": osm.get("name"), "accuracy": osm.get("accuracy")}
                    )
            for proto in self.pm[host].all_protocols():
                for port in sorted(self.pm[host][proto].keys()):
                    p = self.pm[host][proto][port]
                    info["ports"].append(
                        {
                            "port": port,
                            "protocol": proto,
                            "state": p.get("state"),
                            "service": p.get("name", ""),
                            "product": p.get("product", ""),
                            "version": p.get("version", ""),
                        }
                    )
            hosts_out.append(info)
            if log:
                log(f"[{timestamp()}] Host {host}: {len(info['ports'])} open port(s) found.")
        return hosts_out

    # ------------------------------------------------------------------ #
    # Vulnerability scanning (NSE)
    # ------------------------------------------------------------------ #
    def scan_vulnerabilities(self, target: str, log=None):
        """Run NSE 'vuln' category scripts and parse findings per host/port."""
        if log:
            log(f"[{timestamp()}] Running NSE vulnerability scripts on {target} ...")
        self.pm.scan(hosts=target, arguments=self.VULN_ARGS)
        return self._parse_vulns(log)

    def _parse_vulns(self, log=None):
        findings = []
        for host in self.pm.all_hosts():
            for proto in self.pm[host].all_protocols():
                for port in sorted(self.pm[host][proto].keys()):
                    port_info = self.pm[host][proto][port]
                    scripts = port_info.get("script", {})
                    for script_name, output in scripts.items():
                        if "VULNERABLE" not in output and "CVE" not in output.upper():
                            continue
                        cves = extract_cves(output)
                        risk = classify_risk(text=output)
                        findings.append(
                            {
                                "host": host,
                                "port": port,
                                "protocol": proto,
                                "service": port_info.get("name", ""),
                                "script": script_name,
                                "output": output.strip(),
                                "cves": cves,
                                "risk": risk,
                            }
                        )
            if log:
                host_findings = [f for f in findings if f["host"] == host]
                log(f"[{timestamp()}] {host}: {len(host_findings)} potential finding(s).")
        return findings

    # ------------------------------------------------------------------ #
    # Combined workflow
    # ------------------------------------------------------------------ #
    def run_full_scan(self, target: str, log=None):
        """Run discovery followed by vulnerability scanning; return a report dict."""
        hosts = self.discover(target, log=log)
        findings = self.scan_vulnerabilities(target, log=log)
        return {
            "target": target,
            "timestamp": timestamp(),
            "hosts": hosts,
            "findings": findings,
        }


def nmap_version() -> str:
    """Return the installed nmap binary's version string, or an error note."""
    if shutil.which("nmap") is None:
        return "nmap not found on PATH"
    try:
        out = subprocess.run(
            ["nmap", "--version"], capture_output=True, text=True, timeout=10
        )
        return out.stdout.splitlines()[0] if out.stdout else "unknown"
    except Exception as exc:  # pragma: no cover - defensive
        return f"error: {exc}"
