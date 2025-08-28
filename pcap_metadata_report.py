#!/usr/bin/env python3
"""
pcap_metadata_report.py — Attacker’s-view metadata report generator for PCAPs (enhanced)

Outputs (in the chosen output directory):
  - devices.csv              : MAC, vendor (from OUI), IPs seen, first/last seen, packet count
  - dns_queries.csv          : time_epoch, client_ip, query, qtype
  - tls_sni.csv              : time_epoch, src_ip, dst_ip, server_name_indication
  - http_requests.csv        : time_epoch, src_ip, host, method, uri, user_agent, has_auth_header
  - protocols.csv            : protocol_name, packet_count
  - timeline_<res>.csv       : bucket_epoch, packet_count   (res ∈ {second,minute,hour})
  - summary.json             : aggregate stats (top domains, top SNI, device counts, time span, etc.)

Why metadata?
  Even with TLS, you still see who/what/when: DNS, SNI, server IPs, device vendors from MAC OUIs.
  This script demonstrates how much recon is possible without decrypting payloads.

Requirements:
  - Python 3.9+
  - tshark (Wireshark CLI) installed and on PATH
  - pyshark  (apt: python3-pyshark, or pip)
  - manuf    (apt: python3-manuf, or pip)  # offline MAC OUI vendor lookup

Usage:
  python3 pcap_metadata_report.py -r capture.pcap -o ./report_out
  # Useful flags:
  #   --limit 50000                     Process only first N packets
  #   --sample-rate 10                  Process every 10th packet (for huge pcaps)
  #   --timeline-resolution minute      Aggregate timeline by second|minute|hour (default: minute)
  #   --top-n 15                        How many “top” items to include in summary.json (default: 15)
  #   --oui-file ./manuf                Use a custom manuf OUI file
  #   --no-http / --no-tls / --no-dns   Skip parsing of those protocols
  #   --iface-ip-only                   Ignore MAC ledger entirely (IP-only mode)
"""

import argparse
import csv
import json
import os
import sys
import time
from collections import Counter
from datetime import timedelta

# Third-party
try:
    import pyshark
except ImportError:
    print("❌ pyshark is not installed. Install via apt (python3-pyshark) or pip.", file=sys.stderr)
    sys.exit(1)

try:
    from manuf import manuf
except ImportError:
    print("❌ manuf is not installed. Install via apt (python3-manuf) or pip.", file=sys.stderr)
    sys.exit(1)


# ------------------------- Utilities -------------------------

def ensure_tshark():
    from shutil import which
    if which("tshark") is None:
        print("❌ tshark (Wireshark CLI) not found. Install Wireshark/tshark and ensure it's on PATH.", file=sys.stderr)
        sys.exit(1)


def safe_get(layer, attr):
    try:
        val = getattr(layer, attr, "")
        return str(val) if val is not None else ""
    except Exception:
        return ""


def bucket_epoch(epoch: float, resolution: str) -> int:
    if resolution == "second":
        size = 1
    elif resolution == "hour":
        size = 3600
    else:
        size = 60  # minute
    return int(epoch // size * size)


def write_csv(path, headers, rows_iterable):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(headers)
        for row in rows_iterable:
            w.writerow(row)


def human_duration(seconds: float) -> str:
    try:
        return str(timedelta(seconds=int(seconds)))
    except Exception:
        return f"{seconds:.2f}s"


def is_broadcast_or_multicast_mac(mac: str) -> bool:
    if not mac:
        return True
    mac_l = mac.lower()
    return mac_l == "ff:ff:ff:ff:ff:ff" or mac_l.startswith("33:33:")


# ------------------------- Main -------------------------

def main():
    parser = argparse.ArgumentParser(description="Generate attacker’s-view metadata reports from a PCAP.")
    parser.add_argument("-r", "--pcap", required=True, help="Input PCAP file")
    parser.add_argument("-o", "--outdir", required=True, help="Output directory for CSV/JSON reports")

    # Performance / scale
    parser.add_argument("--limit", type=int, default=0, help="Process only first N packets (0 = no limit)")
    parser.add_argument("--sample-rate", type=int, default=1,
                        help="Process every Nth packet (>=1). Useful for huge pcaps.")

    # Content toggles
    parser.add_argument("--iface-ip-only", action="store_true", help="Only record IPs (ignore MAC ledger)")
    parser.add_argument("--no-http", action="store_true", help="Skip HTTP parsing (faster)")
    parser.add_argument("--no-tls", action="store_true", help="Skip TLS SNI parsing (faster)")
    parser.add_argument("--no-dns", action="store_true", help="Skip DNS parsing (faster)")

    # Aggregation / summary
    parser.add_argument("--timeline-resolution", choices=["second", "minute", "hour"], default="minute",
                        help="Timeline bucket resolution")
    parser.add_argument("--top-n", type=int, default=15, help="Top-N items in summary.json")

    # OUI / vendor enrichment
    parser.add_argument("--oui-file", default=None, help="Path to a manuf-format OUI file (optional override)")

    args = parser.parse_args()
    if args.sample_rate < 1:
        print("❌ --sample-rate must be >= 1", file=sys.stderr)
        sys.exit(1)

    ensure_tshark()

    outdir = os.path.abspath(args.outdir)
    os.makedirs(outdir, exist_ok=True)

    # OUI vendor resolver
    try:
        oui = manuf.MacParser(args.oui_file) if args.oui_file else manuf.MacParser()
    except Exception as e:
        print(f"⚠️  Failed to load OUI file: {e}. Falling back to default.", file=sys.stderr)
        oui = manuf.MacParser()

    # Aggregates
    mac_ledger = {}
    proto_counts = Counter()
    timeline_counts = Counter()
    unique_ips = set()

    dns_rows, tls_rows, http_rows = [], [], []

    # Pyshark capture
    display_filter = "eth || ip || ipv6"
    custom_parameters = {"use_json": True, "include_raw": False}
    try:
        cap = pyshark.FileCapture(args.pcap, display_filter=display_filter,
                                  keep_packets=False, **custom_parameters)
    except Exception as e:
        print(f"❌ Failed to open PCAP with pyshark: {e}", file=sys.stderr)
        sys.exit(1)

    start_time = time.time()
    processed, iter_index = 0, 0
    first_epoch, last_epoch = None, None

    try:
        for pkt in cap:
            iter_index += 1
            if args.sample_rate > 1 and (iter_index % args.sample_rate != 0):
                continue

            try:
                ts = float(getattr(pkt, "sniff_timestamp", getattr(pkt, "sniff_time", time.time())))
                if first_epoch is None:
                    first_epoch = ts
                last_epoch = ts
                timeline_counts[bucket_epoch(ts, args.timeline_resolution)] += 1

                if getattr(pkt, "highest_layer", ""):
                    proto_counts[pkt.highest_layer] += 1

                # Ethernet / MACs
                if not args.iface_ip_only and hasattr(pkt, "eth"):
                    for mac in (safe_get(pkt.eth, "src"), safe_get(pkt.eth, "dst")):
                        if mac and not is_broadcast_or_multicast_mac(mac):
                            if mac not in mac_ledger:
                                mac_ledger[mac] = {
                                    "vendor": oui.get_manuf(mac) or "Unknown Vendor",
                                    "ips": set(),
                                    "first_seen": ts,
                                    "last_seen": ts,
                                    "pkts": 1
                                }
                            else:
                                e = mac_ledger[mac]
                                e["last_seen"], e["pkts"] = ts, e["pkts"] + 1

                # IPs
                src_ip, dst_ip = "", ""
                if hasattr(pkt, "ip"):
                    src_ip, dst_ip = safe_get(pkt.ip, "src"), safe_get(pkt.ip, "dst")
                elif hasattr(pkt, "ipv6"):
                    src_ip, dst_ip = safe_get(pkt.ipv6, "src"), safe_get(pkt.ipv6, "dst")

                if src_ip: unique_ips.add(src_ip)
                if dst_ip: unique_ips.add(dst_ip)

                if not args.iface_ip_only and hasattr(pkt, "eth"):
                    es, ed = safe_get(pkt.eth, "src"), safe_get(pkt.eth, "dst")
                    if es in mac_ledger and src_ip: mac_ledger[es]["ips"].add(src_ip)
                    if ed in mac_ledger and dst_ip: mac_ledger[ed]["ips"].add(dst_ip)

                # DNS
                if not args.no_dns and hasattr(pkt, "dns"):
                    if safe_get(pkt.dns, "flags_response") == "0":
                        qname, qtype = safe_get(pkt.dns, "qry_name"), safe_get(pkt.dns, "qry_type")
                        if qname: dns_rows.append((f"{ts:.6f}", src_ip, qname.lower(), qtype))

                # TLS SNI
                if not args.no_tls:
                    sni = ""
                    if hasattr(pkt, "tls"):
                        sni = safe_get(pkt.tls, "handshake_extensions_server_name")
                    if not sni and hasattr(pkt, "ssl"):
                        sni = safe_get(pkt.ssl, "handshake_extensions_server_name")
                    if sni: tls_rows.append((f"{ts:.6f}", src_ip, dst_ip, sni.lower()))

                # HTTP
                if not args.no_http and hasattr(pkt, "http"):
                    method = safe_get(pkt.http, "request_method")
                    if method:
                        host, uri, ua = safe_get(pkt.http, "host").lower(), safe_get(pkt.http, "request_uri"), safe_get(pkt.http, "user_agent")
                        has_auth = "true" if safe_get(pkt.http, "authorization") else "false"
                        http_rows.append((f"{ts:.6f}", src_ip, host, method, uri, ua, has_auth))

                processed += 1
                if args.limit and processed >= args.limit:
                    break
            except Exception:
                continue
    finally:
        try: cap.close()
        except Exception: pass

    # ----------------- Write reports -----------------

    # devices.csv
    device_rows = [[mac, e["vendor"], ";".join(sorted(e["ips"])),
                    f"{e['first_seen']:.6f}", f"{e['last_seen']:.6f}", e["pkts"]]
                   for mac, e in sorted(mac_ledger.items(), key=lambda kv: kv[1]["pkts"], reverse=True)]
    write_csv(os.path.join(outdir, "devices.csv"),
              ["mac", "vendor", "ips_seen", "first_seen_epoch", "last_seen_epoch", "packet_count"],
              device_rows)

    write_csv(os.path.join(outdir, "dns_queries.csv"),
              ["time_epoch", "client_ip", "query", "qtype"], dns_rows)

    write_csv(os.path.join(outdir, "tls_sni.csv"),
              ["time_epoch", "src_ip", "dst_ip", "sni_hostname"], tls_rows)

    write_csv(os.path.join(outdir, "http_requests.csv"),
              ["time_epoch", "src_ip", "host", "method", "uri", "user_agent", "has_auth_header"], http_rows)

    write_csv(os.path.join(outdir, "protocols.csv"),
              ["protocol", "packet_count"],
              sorted(proto_counts.items(), key=lambda kv: kv[1], reverse=True))

    timeline_file = f"timeline_{args.timeline_resolution}.csv"
    write_csv(os.path.join(outdir, timeline_file),
              [f"{args.timeline_resolution}_epoch", "packet_count"],
              sorted(timeline_counts.items()))

    # summary.json
    def topn(seq, n): return Counter(seq).most_common(n)
    n = max(1, args.top_n)
    top_dns = [{"domain": d, "count": c} for d, c in topn([r[2] for r in dns_rows], n)]
    top_sni = [{"hostname": h, "count": c} for h, c in topn([r[3] for r in tls_rows], n)]
    top_http_hosts = [{"host": h, "count": c} for h, c in topn([r[2] for r in http_rows], n)]

    capture_secs = (last_epoch - first_epoch) if (first_epoch and last_epoch) else 0.0
    summary = {
        "input_pcap": os.path.abspath(args.pcap),
        "outdir": outdir,
        "processed_packets": processed,
        "duration_seconds": round(capture_secs, 3),
        "duration_human": human_duration(capture_secs),
        "time_span_epoch": {"first": first_epoch, "last": last_epoch},
        "timeline_resolution": args.timeline_resolution,
        "device_count": len(mac_ledger),
        "unique_ip_count": len(unique_ips),
        "top_dns_queries": top_dns,
        "top_tls_sni": top_sni,
        "top_http_hosts": top_http_hosts,
        "protocol_mix_top": [{"protocol": p, "count": c}
                             for p, c in sorted(proto_counts.items(), key=lambda kv: kv[1], reverse=True)[:n]],
        "notes": [
            "MAC vendor inference uses the manuf (IEEE OUI) database.",
            "SNI is visible from TLS ClientHello unless Encrypted Client Hello is used.",
            "DNS queries leak domains unless DoH/DoT is enforced.",
            f"Sampling: every {args.sample_rate} packet(s)."
        ]
    }
    with open(os.path.join(outdir, "summary.json"), "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    # Console summary
    print(f"✅ Reports written to: {outdir}")
    print(f"   Packets processed    : {processed} (sample-rate: {args.sample_rate}, limit: {args.limit or 'none'})")
    if first_epoch and last_epoch:
        s, e = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(first_epoch)), time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(last_epoch))
        print(f"   Capture window (UTC) : {s}Z → {e}Z  ({human_duration(capture_secs)})")
    print(f"   Devices (unique MACs): {len(mac_ledger)}")
    print(f"   Unique IPs observed  : {len(unique_ips)}")
    if top_dns: print(f"   Top DNS: {', '.join(d['domain'] for d in top_dns[:5])}")
    if top_sni: print(f"   Top SNI: {', '.join(h['hostname'] for h in top_sni[:5])}")

if __name__ == "__main__":
    main()
