#!/usr/bin/env python3
"""
pcap_metadata_report.py — Attacker’s-view metadata report generator for PCAPs

Outputs (in the chosen output directory):
  - devices.csv            : MAC, vendor (from OUI), IPs seen, first/last seen, packet count
  - dns_queries.csv        : time_epoch, client_ip, query, qtype
  - tls_sni.csv            : time_epoch, src_ip, dst_ip, server_name_indication
  - http_requests.csv      : time_epoch, src_ip, host, method, uri, user_agent, has_auth_header
  - protocols.csv          : protocol_name, packet_count
  - timeline_minute.csv    : minute_epoch, packet_count
  - summary.json           : aggregate stats (top domains, top SNI, device counts, time span)

Why metadata?
  Even with TLS, you still see who/what/when: DNS, SNI, server IPs, device vendors from MAC OUIs.
  This script helps demonstrate exactly how much recon is possible without decrypting payloads.

Requirements:
  - Python 3.9+
  - tshark (Wireshark CLI) installed and on PATH
  - pyshark  (pip install pyshark)
  - manuf    (pip install manuf)  # offline MAC OUI vendor lookup

Usage:
  python3 pcap_metadata_report.py -r capture.pcap -o ./report_out
  # optional flags: --limit 50000 (process first N packets), --iface-ip-only (ignore IPv6)
"""

import argparse
import csv
import json
import os
import sys
import time
from collections import Counter, defaultdict

# Third-party
try:
    import pyshark
except ImportError:
    print("❌ pyshark is not installed. Run: pip install pyshark", file=sys.stderr)
    sys.exit(1)

try:
    from manuf import manuf
except ImportError:
    print("❌ manuf is not installed. Run: pip install manuf", file=sys.stderr)
    sys.exit(1)


def ensure_tshark():
    """Fail fast if tshark isn't available (pyshark depends on it)."""
    from shutil import which
    if which("tshark") is None:
        print("❌ tshark (Wireshark CLI) not found. Install Wireshark or tshark and ensure it's on PATH.", file=sys.stderr)
        sys.exit(1)


def safe_get(layer, attr):
    """Return string value of a pyshark layer attribute if present, else ''."""
    try:
        val = getattr(layer, attr, "")
        return str(val) if val is not None else ""
    except Exception:
        return ""


def epoch_floor_minute(epoch: float) -> int:
    return int(epoch // 60 * 60)


def write_csv(path, headers, rows_iterable):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(headers)
        for row in rows_iterable:
            w.writerow(row)


def main():
    parser = argparse.ArgumentParser(description="Generate attacker’s-view metadata reports from a PCAP.")
    parser.add_argument("-r", "--pcap", required=True, help="Input PCAP file")
    parser.add_argument("-o", "--outdir", required=True, help="Output directory for CSV/JSON reports")
    parser.add_argument("--limit", type=int, default=0, help="Process only first N packets (0 = no limit)")
    parser.add_argument("--iface-ip-only", action="store_true", help="Only record IPv4/IPv6 IPs (ignore MAC ledger if desired)")
    parser.add_argument("--no-http", action="store_true", help="Skip HTTP parsing (faster)")
    parser.add_argument("--no-tls", action="store_true", help="Skip TLS SNI parsing (faster)")
    parser.add_argument("--no-dns", action="store_true", help="Skip DNS parsing (faster)")
    args = parser.parse_args()

    ensure_tshark()

    outdir = os.path.abspath(args.outdir)
    os.makedirs(outdir, exist_ok=True)

    # Device/vendor resolver
    oui = manuf.MacParser()

    # Aggregates
    mac_ledger = {}  # mac -> dict(vendor, ips:set, first_seen, last_seen, pkts)
    proto_counts = Counter()
    timeline_minute = Counter()

    dns_rows = []
    tls_rows = []
    http_rows = []

    # Hints for pyshark to be efficient
    display_filter = "eth || ip || ipv6"
    custom_parameters = {
        # Reduce overhead; adjust if you need reassembly etc.
        "use_json": True,
        "include_raw": False
    }

    # Stream the capture (no in-memory retention)
    try:
        cap = pyshark.FileCapture(
            args.pcap,
            display_filter=display_filter,
            keep_packets=False,
            **custom_parameters
        )
    except Exception as e:
        print(f"❌ Failed to open PCAP with pyshark: {e}", file=sys.stderr)
        sys.exit(1)

    start_time = time.time()
    processed = 0
    first_epoch = None
    last_epoch = None

    for pkt in cap:
        try:
            # Timing
            ts = float(getattr(pkt, "sniff_timestamp", getattr(pkt, "sniff_time", time.time())))
            if first_epoch is None:
                first_epoch = ts
            last_epoch = ts
            timeline_minute[epoch_floor_minute(ts)] += 1

            # Highest-layer / protocol column approximation
            try:
                highest = getattr(pkt, "highest_layer", "")
                if highest:
                    proto_counts[highest] += 1
            except Exception:
                pass

            # Ethernet (MACs)
            if not args.iface_ip_only and hasattr(pkt, "eth"):
                src_mac = safe_get(pkt.eth, "src")
                dst_mac = safe_get(pkt.eth, "dst")
                for mac in (src_mac, dst_mac):
                    if mac and mac != "ff:ff:ff:ff:ff:ff":
                        if mac not in mac_ledger:
                            vendor = oui.get_manuf(mac) or "Unknown Vendor"
                            mac_ledger[mac] = {
                                "vendor": vendor,
                                "ips": set(),
                                "first_seen": ts,
                                "last_seen": ts,
                                "pkts": 1
                            }
                        else:
                            entry = mac_ledger[mac]
                            entry["last_seen"] = ts
                            entry["pkts"] += 1

            # IP addresses
            src_ip = dst_ip = ""
            if hasattr(pkt, "ip"):
                src_ip = safe_get(pkt.ip, "src")
                dst_ip = safe_get(pkt.ip, "dst")
            elif hasattr(pkt, "ipv6"):
                src_ip = safe_get(pkt.ipv6, "src")
                dst_ip = safe_get(pkt.ipv6, "dst")

            # Tie IPs back to MAC entries when we can (best-effort)
            if not args.iface_ip_only and hasattr(pkt, "eth"):
                eth_src = safe_get(pkt.eth, "src")
                eth_dst = safe_get(pkt.eth, "dst")
                if eth_src in mac_ledger and src_ip:
                    mac_ledger[eth_src]["ips"].add(src_ip)
                if eth_dst in mac_ledger and dst_ip:
                    mac_ledger[eth_dst]["ips"].add(dst_ip)

            # DNS (queries only)
            if not args.no_dns and hasattr(pkt, "dns"):
                # Only record queries (qr==0)
                qr = safe_get(pkt.dns, "flags_response")  # "0" for query, "1" for response
                if qr == "0":
                    qname = safe_get(pkt.dns, "qry_name")
                    qtype = safe_get(pkt.dns, "qry_type")
                    if qname:
                        dns_rows.append((f"{ts:.6f}", src_ip, qname.lower(), qtype))

            # TLS SNI (ClientHello)
            if not args.no_tls:
                server_name = ""
                # Newer Wireshark: tls fields; older builds: ssl.*
                if hasattr(pkt, "tls"):
                    server_name = safe_get(pkt.tls, "handshake_extensions_server_name")
                if not server_name and hasattr(pkt, "ssl"):
                    server_name = safe_get(pkt.ssl, "handshake_extensions_server_name")
                if server_name:
                    tls_rows.append((f"{ts:.6f}", src_ip, dst_ip, server_name.lower()))

            # HTTP (requests only)
            if not args.no_http and hasattr(pkt, "http"):
                method = safe_get(pkt.http, "request_method")
                if method:
                    host = safe_get(pkt.http, "host").lower()
                    uri = safe_get(pkt.http, "request_uri")
                    ua = safe_get(pkt.http, "user_agent")
                    has_auth = "true" if safe_get(pkt.http, "authorization") else "false"
                    http_rows.append((f"{ts:.6f}", src_ip, host, method, uri, ua, has_auth))

            processed += 1
            if args.limit and processed >= args.limit:
                break

        except Exception:
            # Keep streaming even if a packet is malformed or fields are missing
            continue

    # Close capture cleanly
    try:
        cap.close()
    except Exception:
        pass

    # ---- Write reports ----
    # devices.csv
    device_rows = []
    for mac, entry in sorted(mac_ledger.items(), key=lambda kv: kv[1]["pkts"], reverse=True):
        ips_joined = ";".join(sorted(entry["ips"])) if entry["ips"] else ""
        device_rows.append([
            mac,
            entry["vendor"],
            ips_joined,
            f"{entry['first_seen']:.6f}",
            f"{entry['last_seen']:.6f}",
            entry["pkts"],
        ])
    write_csv(os.path.join(outdir, "devices.csv"),
              ["mac", "vendor", "ips_seen", "first_seen_epoch", "last_seen_epoch", "packet_count"],
              device_rows)

    # dns_queries.csv
    write_csv(os.path.join(outdir, "dns_queries.csv"),
              ["time_epoch", "client_ip", "query", "qtype"],
              dns_rows)

    # tls_sni.csv
    write_csv(os.path.join(outdir, "tls_sni.csv"),
              ["time_epoch", "src_ip", "dst_ip", "sni_hostname"],
              tls_rows)

    # http_requests.csv
    write_csv(os.path.join(outdir, "http_requests.csv"),
              ["time_epoch", "src_ip", "host", "method", "uri", "user_agent", "has_auth_header"],
              http_rows)

    # protocols.csv
    write_csv(os.path.join(outdir, "protocols.csv"),
              ["protocol", "packet_count"],
              sorted(proto_counts.items(), key=lambda kv: kv[1], reverse=True))

    # timeline_minute.csv
    write_csv(os.path.join(outdir, "timeline_minute.csv"),
              ["minute_epoch", "packet_count"],
              sorted(timeline_minute.items()))

    # summary.json (top-Ns and stats)
    def topn(seq, n=15):
        return Counter(seq).most_common(n)

    top_dns = [ {"domain": d, "count": c} for d, c in topn([r[2] for r in dns_rows]) ]
    top_sni = [ {"hostname": h, "count": c} for h, c in topn([r[3] for r in tls_rows]) ]
    top_http_hosts = [ {"host": h, "count": c} for h, c in topn([r[2] for r in http_rows]) ]
    device_count = len(mac_ledger)

    summary = {
        "input_pcap": os.path.abspath(args.pcap),
        "outdir": outdir,
        "processed_packets": processed,
        "duration_seconds": round(time.time() - start_time, 3),
        "time_span_epoch": {
            "first": float(f"{first_epoch:.6f}") if first_epoch else None,
            "last": float(f"{last_epoch:.6f}") if last_epoch else None
        },
        "device_count": device_count,
        "top_dns_queries": top_dns,
        "top_tls_sni": top_sni,
        "top_http_hosts": top_http_hosts,
        "protocol_mix_top": [{"protocol": p, "count": c} for p, c in sorted(proto_counts.items(), key=lambda kv: kv[1], reverse=True)[:15]],
        "notes": [
            "MAC vendor inference uses the manuf (IEEE OUI) database.",
            "SNI is visible from TLS ClientHello unless Encrypted Client Hello is used.",
            "DNS queries leak domains unless DNS-over-HTTPS/DoT is enforced."
        ]
    }
    with open(os.path.join(outdir, "summary.json"), "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    print(f"✅ Done. Wrote reports to: {outdir}")
    print(f"   Packets processed: {processed}")
    if first_epoch and last_epoch:
        print(f"   Capture window: {time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(first_epoch))}Z  →  {time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(last_epoch))}Z")
    print(f"   Devices found: {device_count}")
    if top_dns:
        print(f"   Top DNS: {', '.join(d['domain'] for d in top_dns[:5])}")
    if top_sni:
        print(f"   Top SNI: {', '.join(h['hostname'] for h in top_sni[:5])}")
