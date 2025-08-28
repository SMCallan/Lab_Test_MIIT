#!/usr/bin/env python3
"""
Lab Orchestrator: run MITM for a fixed duration, then build report + dashboard.

Flow:
  1) Start mitm_solv2.py (your existing MITM lab script).
  2) Countdown for --duration seconds (default 300 = 5 min).
  3) Stop MITM cleanly (SIGINT to the whole process group).
  4) Run pcap_metadata_report.py to generate CSV/JSON.
  5) Run pcap_report_dashboard.py to produce a static HTML report.
  6) Optionally open the HTML in the default browser.

⚠️ For authorized lab use only.
"""

import argparse
import os
import signal
import subprocess
import sys
import time
from shutil import which

def check_cmd(name):
    if which(name) is None:
        print(f"❌ Required command '{name}' not found in PATH.")
        sys.exit(1)

def check_file(path, label):
    if not os.path.exists(path):
        print(f"❌ {label} not found: {path}")
        sys.exit(1)

def kill_process_group(p, grace=5):
    """Send SIGINT → wait → SIGTERM → wait → SIGKILL (if needed)."""
    try:
        pgid = os.getpgid(p.pid)
    except Exception:
        pgid = None

    def _send(sig):
        try:
            if pgid:
                os.killpg(pgid, sig)
            else:
                p.send_signal(sig)
        except Exception:
            pass

    _send(signal.SIGINT)
    try:
        p.wait(timeout=grace)
        return
    except subprocess.TimeoutExpired:
        pass

    _send(signal.SIGTERM)
    try:
        p.wait(timeout=grace)
        return
    except subprocess.TimeoutExpired:
        pass

    _send(signal.SIGKILL)
    try:
        p.wait(timeout=2)
    except Exception:
        pass

def run_checked(cmd, cwd=None):
    print(f"▶ {' '.join(cmd)}")
    subprocess.run(cmd, check=True, cwd=cwd)

def main():
    ap = argparse.ArgumentParser(description="Run MITM for a fixed time, then generate report + dashboard.")
    ap.add_argument("--mitm-script", default="mitm_solv2.py", help="Path to the MITM script to run")
    ap.add_argument("--pcap", default="mitm_capture.pcap", help="Expected pcap output from the MITM script")
    ap.add_argument("--duration", type=int, default=300, help="Run time in seconds (default 300 = 5 minutes)")
    ap.add_argument("--outdir", default="report_out", help="Report output directory")
    ap.add_argument("--timeline-resolution", choices=["second", "minute", "hour"], default="minute",
                    help="Timeline bucket resolution for the report")
    ap.add_argument("--top-n", type=int, default=15, help="Top-N items to include in summary.json")
    ap.add_argument("--sample-rate", type=int, default=1, help="Process every Nth packet when reporting")
    ap.add_argument("--open", action="store_true", help="Open the HTML dashboard when finished")
    ap.add_argument("--dashboard", default="attacker_view.html", help="Output dashboard HTML filename")
    args = ap.parse_args()

    # —— Preflight checks
    check_file(args.mitm_script, "MITM script")
    check_cmd("python3")
    # These are Python scripts; ensure they exist locally.
    check_file("pcap_metadata_report.py", "pcap_metadata_report.py")
    check_file("pcap_report_dashboard.py", "pcap_report_dashboard.py")

    # —— Start MITM script in its own process group (so we can stop everything cleanly)
    print(f"[*] Launching MITM script: {args.mitm_script}")
    try:
        p = subprocess.Popen(
            ["python3", args.mitm_script],
            preexec_fn=os.setsid if hasattr(os, "setsid") else None,
        )
    except FileNotFoundError:
        print("❌ Could not start MITM script with python3.")
        sys.exit(1)

    # —— Countdown
    print(f"[*] Running for {args.duration} seconds. Press Ctrl+C to abort early.")
    start = time.time()
    try:
        while True:
            elapsed = int(time.time() - start)
            remaining = args.duration - elapsed
            if remaining <= 0:
                break
            # Lightweight “live” countdown line
            sys.stdout.write(f"\r   ⏳ Time remaining: {remaining:4d}s ")
            sys.stdout.flush()
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[!] Aborted by operator. Stopping MITM …")

    # —— Stop MITM
    print("\n[*] Stopping MITM script …")
    kill_process_group(p)

    # —— Ensure the pcap exists (give tcpdump a moment to flush)
    for _ in range(5):
        if os.path.exists(args.pcap) and os.path.getsize(args.pcap) > 0:
            break
        time.sleep(0.5)

    check_file(args.pcap, "PCAP file")

    # —— Run metadata report
    print("[*] Generating metadata report …")
    report_cmd = [
        "python3", "pcap_metadata_report.py",
        "-r", args.pcap,
        "-o", args.outdir,
        "--timeline-resolution", args.timeline_resolution,
        "--top-n", str(args.top_n),
        "--sample-rate", str(args.sample_rate),
    ]
    run_checked(report_cmd)

    # —— Build dashboard
    summary_path = os.path.join(args.outdir, "summary.json")
    check_file(summary_path, "summary.json")

    print("[*] Building dashboard …")
    dash_cmd = [
        "python3", "pcap_report_dashboard.py",
        "-i", summary_path,
        "-o", args.dashboard
    ]
    run_checked(dash_cmd)

    # —— Optionally open
    if args.open:
        opener = None
        if which("xdg-open"): opener = "xdg-open"
        elif which("open"):   opener = "open"       # macOS
        if opener:
            try:
                subprocess.Popen([opener, args.dashboard])
            except Exception:
                pass

    print(f"\n✅ Done.\n   PCAP     : {os.path.abspath(args.pcap)}"
          f"\n   Reports  : {os.path.abspath(args.outdir)}"
          f"\n   Dashboard: {os.path.abspath(args.dashboard)}")

if __name__ == "__main__":
    main()
