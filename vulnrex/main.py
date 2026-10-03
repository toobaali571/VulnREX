"""
main.py
VulnREX desktop GUI (Tkinter).

Tabs:
  1. Scan       - enter a target, run discovery + NSE vuln scan, view live log
  2. Findings   - sortable table of vulnerability findings with risk color-coding
  3. Reverse Eng- pick an executable, run static triage, open Ghidra GUI, or run Ghidra headless
  4. History    - past scans saved to disk, reload / re-export as PDF

Run with:  python -m vulnrex.main
"""

import os
import sys
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from vulnrex.scanner import NmapScanner, ScannerError, nmap_version
from vulnrex.re_module import (
    find_ghidra_install, launch_ghidra_gui, run_headless_analysis,
    quick_triage, REError,
)
from vulnrex.report_generator import build_report
from vulnrex.utils import (
    is_valid_target, save_json, load_json, ensure_dir, timestamp, risk_rank
)

APP_DIR = os.path.expanduser("~/.vulnrex")
HISTORY_DIR = ensure_dir(os.path.join(APP_DIR, "history"))
REPORTS_DIR = ensure_dir(os.path.join(APP_DIR, "reports"))

RISK_COLORS = {
    "Critical": "#b00020",
    "High": "#e65100",
    "Medium": "#f9a825",
    "Low": "#2e7d32",
    "Informational": "#546e7a",
}


class VulnrexApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("VulnREX — Vulnerability Assessment & Reverse Engineering Toolkit")
        self.geometry("1000x700")
        self.minsize(860, 600)

        self.current_scan = None          # last scan_result dict
        self.current_re_findings = []      # list of triage dicts for the report
        self.ghidra_home = find_ghidra_install()

        self._build_style()
        self._build_layout()

    # ------------------------------------------------------------------ #
    def _build_style(self):
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("TNotebook.Tab", padding=(14, 6))
        style.configure("Treeview", rowheight=24)

    def _build_layout(self):
        notebook = ttk.Notebook(self)
        notebook.pack(fill="both", expand=True, padx=8, pady=8)

        self.scan_tab = ttk.Frame(notebook)
        self.findings_tab = ttk.Frame(notebook)
        self.re_tab = ttk.Frame(notebook)
        self.history_tab = ttk.Frame(notebook)

        notebook.add(self.scan_tab, text="Scan")
        notebook.add(self.findings_tab, text="Findings")
        notebook.add(self.re_tab, text="Reverse Engineering")
        notebook.add(self.history_tab, text="History")

        self._build_scan_tab()
        self._build_findings_tab()
        self._build_re_tab()
        self._build_history_tab()

        # status bar
        self.status_var = tk.StringVar(value=f"Ready — {nmap_version()}")
        status = ttk.Label(self, textvariable=self.status_var, anchor="w", relief="sunken")
        status.pack(fill="x", side="bottom")

    # ------------------------------------------------------------------ #
    # Scan tab
    # ------------------------------------------------------------------ #
    def _build_scan_tab(self):
        frm = self.scan_tab
        top = ttk.Frame(frm)
        top.pack(fill="x", padx=10, pady=10)

        ttk.Label(top, text="Target (IP / hostname / CIDR):").pack(side="left")
        self.target_entry = ttk.Entry(top, width=30)
        self.target_entry.pack(side="left", padx=8)
        self.target_entry.insert(0, "127.0.0.1")

        self.scan_btn = ttk.Button(top, text="Run Full Scan", command=self.on_run_scan)
        self.scan_btn.pack(side="left", padx=6)

        ttk.Label(
            frm,
            text=("Only scan systems you own or are explicitly authorized to test. "
                  "Unauthorized scanning may be illegal."),
            foreground="#b00020",
        ).pack(anchor="w", padx=10)

        self.log_text = tk.Text(frm, height=28, bg="#0d1117", fg="#c9d1d9",
                                 insertbackground="#c9d1d9")
        self.log_text.pack(fill="both", expand=True, padx=10, pady=10)
        self.log_text.configure(state="disabled")

    def gui_log(self, message: str):
        def append():
            self.log_text.configure(state="normal")
            self.log_text.insert("end", message + "\n")
            self.log_text.see("end")
            self.log_text.configure(state="disabled")
        self.after(0, append)

    def on_run_scan(self):
        target = self.target_entry.get().strip()
        if not is_valid_target(target):
            messagebox.showerror("Invalid target", "Please enter a valid target (no shell characters).")
            return

        self.scan_btn.configure(state="disabled")
        self.status_var.set(f"Scanning {target} ...")
        self.log_text.configure(state="normal")
        self.log_text.delete("1.0", "end")
        self.log_text.configure(state="disabled")

        thread = threading.Thread(target=self._scan_worker, args=(target,), daemon=True)
        thread.start()

    def _scan_worker(self, target: str):
        try:
            scanner = NmapScanner()
            result = scanner.run_full_scan(target, log=self.gui_log)
            self.current_scan = result
            self.gui_log(f"[{timestamp()}] Scan complete: "
                         f"{len(result['hosts'])} host(s), {len(result['findings'])} finding(s).")
            self._save_history(result)
            self.after(0, self._populate_findings)
            self.after(0, lambda: self.status_var.set("Scan complete."))
        except ScannerError as e:
            self.gui_log(f"[ERROR] {e}")
            self.after(0, lambda: messagebox.showerror("Scanner error", str(e)))
            self.after(0, lambda: self.status_var.set("Scan failed."))
        except Exception as e:  # pragma: no cover - defensive
            self.gui_log(f"[ERROR] Unexpected error: {e}")
            self.after(0, lambda: self.status_var.set("Scan failed."))
        finally:
            self.after(0, lambda: self.scan_btn.configure(state="normal"))

    def _save_history(self, result: dict):
        safe_target = result["target"].replace("/", "_").replace(":", "_")
        fname = f"{safe_target}_{result['timestamp'].replace(':', '-').replace(' ', '_')}.json"
        save_json(result, os.path.join(HISTORY_DIR, fname))
        self.after(0, self._refresh_history_list)

    # ------------------------------------------------------------------ #
    # Findings tab
    # ------------------------------------------------------------------ #
    def _build_findings_tab(self):
        frm = self.findings_tab
        top = ttk.Frame(frm)
        top.pack(fill="x", padx=10, pady=10)
        ttk.Button(top, text="Export PDF Report", command=self.on_export_report).pack(side="left")
        self.findings_summary_var = tk.StringVar(value="No scan loaded.")
        ttk.Label(top, textvariable=self.findings_summary_var).pack(side="left", padx=12)

        cols = ("risk", "host", "port", "service", "script", "cves")
        self.tree = ttk.Treeview(frm, columns=cols, show="headings", selectmode="browse")
        headings = {"risk": "Risk", "host": "Host", "port": "Port", "service": "Service",
                    "script": "NSE Script", "cves": "CVEs"}
        widths = {"risk": 90, "host": 140, "port": 60, "service": 110, "script": 200, "cves": 200}
        for c in cols:
            self.tree.heading(c, text=headings[c])
            self.tree.column(c, width=widths[c])
        self.tree.pack(fill="both", expand=True, padx=10, pady=(0, 6))
        self.tree.bind("<<TreeviewSelect>>", self._on_finding_select)

        for risk, color in RISK_COLORS.items():
            self.tree.tag_configure(risk, foreground=color)

        self.detail_text = tk.Text(frm, height=8)
        self.detail_text.pack(fill="x", padx=10, pady=(0, 10))
        self.detail_text.configure(state="disabled")

    def _populate_findings(self):
        self.tree.delete(*self.tree.get_children())
        if not self.current_scan:
            return
        findings = sorted(
            self.current_scan["findings"], key=lambda f: risk_rank(f["risk"]), reverse=True
        )
        for f in findings:
            self.tree.insert(
                "", "end",
                values=(f["risk"], f["host"], f["port"], f["service"],
                        f["script"], ", ".join(f["cves"]) or "-"),
                tags=(f["risk"],),
            )
        counts = {}
        for f in findings:
            counts[f["risk"]] = counts.get(f["risk"], 0) + 1
        summary = " | ".join(f"{k}: {v}" for k, v in counts.items()) or "No findings"
        self.findings_summary_var.set(summary)
        self._finding_lookup = findings

    def _on_finding_select(self, event=None):
        sel = self.tree.selection()
        if not sel:
            return
        idx = self.tree.index(sel[0])
        f = self._finding_lookup[idx]
        self.detail_text.configure(state="normal")
        self.detail_text.delete("1.0", "end")
        self.detail_text.insert("end", f["output"])
        self.detail_text.configure(state="disabled")

    def on_export_report(self):
        if not self.current_scan:
            messagebox.showinfo("No scan", "Run a scan first.")
            return
        default_name = f"vulnrex_report_{self.current_scan['target'].replace('/', '_')}.pdf"
        path = filedialog.asksaveasfilename(
            initialdir=REPORTS_DIR, initialfile=default_name,
            defaultextension=".pdf", filetypes=[("PDF", "*.pdf")],
        )
        if not path:
            return
        try:
            build_report(self.current_scan, self.current_re_findings, path)
            messagebox.showinfo("Report saved", f"Report written to:\n{path}")
        except Exception as e:
            messagebox.showerror("Report error", str(e))

    # ------------------------------------------------------------------ #
    # Reverse Engineering tab
    # ------------------------------------------------------------------ #
    def _build_re_tab(self):
        frm = self.re_tab
        top = ttk.Frame(frm)
        top.pack(fill="x", padx=10, pady=10)

        ttk.Label(top, text="Ghidra install directory:").grid(row=0, column=0, sticky="w")
        self.ghidra_home_var = tk.StringVar(
            value=self.ghidra_home or "(not found — browse below)"
        )
        ttk.Entry(top, textvariable=self.ghidra_home_var, width=55).grid(row=0, column=1, padx=6)
        ttk.Button(top, text="Browse...", command=self._browse_ghidra).grid(row=0, column=2)

        ttk.Label(top, text="Executable to analyze:").grid(row=1, column=0, sticky="w", pady=(8, 0))
        self.binary_path_var = tk.StringVar()
        ttk.Entry(top, textvariable=self.binary_path_var, width=55).grid(row=1, column=1, padx=6, pady=(8, 0))
        ttk.Button(top, text="Browse...", command=self._browse_binary).grid(row=1, column=2, pady=(8, 0))

        btns = ttk.Frame(frm)
        btns.pack(fill="x", padx=10, pady=6)
        ttk.Button(btns, text="Run Static Triage", command=self.on_triage).pack(side="left")
        ttk.Button(btns, text="Open Ghidra GUI", command=self.on_open_ghidra_gui).pack(side="left", padx=8)
        self.headless_btn = ttk.Button(
            btns, text="Run Ghidra Headless Analysis", command=self.on_run_headless
        )
        self.headless_btn.pack(side="left", padx=8)

        self.re_output = tk.Text(frm, height=28)
        self.re_output.pack(fill="both", expand=True, padx=10, pady=10)

    def _browse_ghidra(self):
        path = filedialog.askdirectory(title="Select Ghidra install directory")
        if path:
            self.ghidra_home = path
            self.ghidra_home_var.set(path)

    def _browse_binary(self):
        path = filedialog.askopenfilename(title="Select executable to analyze")
        if path:
            self.binary_path_var.set(path)

    def on_triage(self):
        """Fast, dependency-free static pre-analysis (no Ghidra needed)."""
        path = self.binary_path_var.get().strip()
        if not path or not os.path.isfile(path):
            messagebox.showerror("Invalid file", "Choose a valid executable first.")
            return
        try:
            result = quick_triage(path)
            self.current_re_findings = [
                r for r in self.current_re_findings if r.get("path") != path
            ] + [result]
            self.re_output.delete("1.0", "end")
            self.re_output.insert("end", f"File: {result['path']}\n")
            self.re_output.insert("end", f"Format: {result['format']}\n")
            self.re_output.insert("end", f"Size: {result['size_bytes']:,} bytes\n\n")
            if result["imports"]:
                self.re_output.insert("end", "Imports (sample):\n")
                self.re_output.insert("end", ", ".join(result["imports"][:30]) + "\n\n")
            self.re_output.insert("end", "Sample strings:\n")
            self.re_output.insert("end", "\n".join(result["sample_strings"]))
        except REError as e:
            messagebox.showerror("Triage error", str(e))

    def on_open_ghidra_gui(self):
        ghidra_home = self.ghidra_home_var.get().strip()
        try:
            launch_ghidra_gui(ghidra_home, log=self.gui_log)
            self.status_var.set("Launched Ghidra GUI — use File > Import to load your binary.")
        except REError as e:
            messagebox.showerror("Launch error", str(e))

    def on_run_headless(self):
        """Run Ghidra headless (analyzeHeadless) in a background thread."""
        ghidra_home = self.ghidra_home_var.get().strip()
        binary_path = self.binary_path_var.get().strip()
        if not binary_path or not os.path.isfile(binary_path):
            messagebox.showerror("Invalid file", "Choose a valid executable first.")
            return

        self.headless_btn.configure(state="disabled")
        self.re_output.delete("1.0", "end")
        self.re_output.insert("end", "Running Ghidra headless analysis, please wait...\n")
        self.status_var.set("Running Ghidra headless analysis ...")

        thread = threading.Thread(
            target=self._headless_worker, args=(ghidra_home, binary_path), daemon=True
        )
        thread.start()

    def _headless_worker(self, ghidra_home: str, binary_path: str):
        try:
            result = run_headless_analysis(ghidra_home, binary_path, log=self.gui_log)
            self.current_re_findings = [
                r for r in self.current_re_findings if r.get("path") != binary_path
            ] + [result]
            self.after(0, lambda: self._display_headless_result(result))
            self.after(0, lambda: self.status_var.set("Ghidra headless analysis complete."))
        except REError as e:
            self.gui_log(f"[ERROR] {e}")
            self.after(0, lambda: messagebox.showerror("Ghidra error", str(e)))
            self.after(0, lambda: self.status_var.set("Ghidra headless analysis failed."))
        finally:
            self.after(0, lambda: self.headless_btn.configure(state="normal"))

    def _display_headless_result(self, result: dict):
        self.re_output.delete("1.0", "end")
        self.re_output.insert("end", f"File: {result.get('path', '')}\n")
        self.re_output.insert("end", f"Program: {result.get('program_name', '')}\n")
        self.re_output.insert("end", f"Language/architecture: {result.get('language', '')}\n")
        funcs = result.get("functions", [])
        self.re_output.insert("end", f"\nFunctions found: {len(funcs)}\n")
        for f in funcs[:40]:
            self.re_output.insert("end", f"  {f['entry']}  {f['name']}\n")
        imports = result.get("imports", [])
        if imports:
            self.re_output.insert("end", "\nImports (sample):\n")
            self.re_output.insert("end", ", ".join(imports[:40]) + "\n")
        strings = result.get("strings", [])
        if strings:
            self.re_output.insert("end", "\nStrings (sample):\n")
            self.re_output.insert("end", "\n".join(strings[:40]))

    # ------------------------------------------------------------------ #
    # History tab
    # ------------------------------------------------------------------ #
    def _build_history_tab(self):
        frm = self.history_tab
        top = ttk.Frame(frm)
        top.pack(fill="x", padx=10, pady=10)
        ttk.Button(top, text="Refresh", command=self._refresh_history_list).pack(side="left")
        ttk.Button(top, text="Load Selected", command=self._load_selected_history).pack(side="left", padx=6)

        self.history_list = tk.Listbox(frm)
        self.history_list.pack(fill="both", expand=True, padx=10, pady=10)
        self._refresh_history_list()

    def _refresh_history_list(self):
        self.history_list.delete(0, "end")
        if not os.path.isdir(HISTORY_DIR):
            return
        for fname in sorted(os.listdir(HISTORY_DIR), reverse=True):
            if fname.endswith(".json"):
                self.history_list.insert("end", fname)

    def _load_selected_history(self):
        sel = self.history_list.curselection()
        if not sel:
            return
        fname = self.history_list.get(sel[0])
        data = load_json(os.path.join(HISTORY_DIR, fname))
        self.current_scan = data
        self._populate_findings()
        messagebox.showinfo("Loaded", f"Loaded scan: {fname}")


def main():
    app = VulnrexApp()
    app.mainloop()


if __name__ == "__main__":
    main()
