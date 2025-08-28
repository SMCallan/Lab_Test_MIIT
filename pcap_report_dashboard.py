#!/usr/bin/env python3
"""
pcap_report_dashboard.py
Generate a polished one-file HTML dashboard from the outputs of pcap_metadata_report.py

Usage:
  python3 pcap_report_dashboard.py -i ./report_out/summary.json -o ./dashboard.html
"""

import argparse
import json
import os
from collections import Counter

TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>PCAP Metadata Dashboard</title>
  <style>
    body { font-family: 'Segoe UI', Arial, sans-serif; margin: 0; background: #f4f6f8; color: #333; }
    header { background: #1e293b; color: #fff; padding: 1em 2em; position: sticky; top: 0; z-index: 100; display:flex; align-items:center; justify-content:space-between; }
    header h1 { margin: 0; font-size: 1.2em; }
    nav a { color: #fff; margin-left: 1em; text-decoration: none; font-size: 0.9em; }
    .container { max-width: 1200px; margin: 2em auto; padding: 0 1em; }
    .card { background: #fff; padding: 1.5em; margin-bottom: 2em; border-radius: 10px; box-shadow: 0 4px 12px rgba(0,0,0,0.05); }
    h2 { border-bottom: 2px solid #eee; padding-bottom: .3em; margin-top: 0; }
    table { width: 100%; border-collapse: collapse; margin-top: 1em; }
    th, td { padding: 8px 10px; border-bottom: 1px solid #ddd; }
    th { background: #f9fafb; text-align: left; position: sticky; top: 0; }
    tr:nth-child(even) { background: #fafafa; }
    input[type="text"] { padding: 6px; margin-bottom: 0.5em; width: 100%; border: 1px solid #ccc; border-radius: 4px; }
    .metrics { display: flex; gap: 1em; flex-wrap: wrap; }
    .metric { flex: 1; min-width: 160px; background: #f1f5f9; border-radius: 8px; padding: 1em; text-align: center; }
    .metric h3 { margin: 0; font-size: 1.3em; color:#111; }
    .metric p { margin: .3em 0 0; font-size: .9em; color: #555; }
    canvas { max-width: 100%; height: 350px; }
  </style>
</head>
<body>
<header>
  <h1>PCAP Metadata Dashboard</h1>
  <nav>
    <a href="#summary">Summary</a>
    <a href="#protocols">Protocols</a>
    <a href="#timeline">Timeline</a>
    <a href="#dns">DNS</a>
    <a href="#sni">TLS SNI</a>
    <a href="#devices">Devices</a>
  </nav>
</header>
<div class="container">

  <div class="card" id="summary">
    <h2>Summary</h2>
    <div class="metrics">
      <div class="metric"><h3 id="packetCount">0</h3><p>Packets</p></div>
      <div class="metric"><h3 id="deviceCount">0</h3><p>Devices</p></div>
      <div class="metric"><h3 id="timeSpan">—</h3><p>Capture Window</p></div>
    </div>
  </div>

  <div class="card" id="protocols">
    <h2>Protocol Mix</h2>
    <canvas id="protocolChart"></canvas>
  </div>

  <div class="card" id="timeline">
    <h2>Traffic Timeline</h2>
    <canvas id="timelineChart"></canvas>
  </div>

  <div class="card" id="dns">
    <h2>Top DNS Queries</h2>
    <input type="text" id="dnsFilter" placeholder="Search DNS…">
    <table id="dnsTable"><thead><tr><th>Domain</th><th>Count</th></tr></thead><tbody></tbody></table>
  </div>

  <div class="card" id="sni">
    <h2>Top TLS SNI</h2>
    <input type="text" id="sniFilter" placeholder="Search Hostnames…">
    <table id="sniTable"><thead><tr><th>Hostname</th><th>Count</th></tr></thead><tbody></tbody></table>
  </div>

  <div class="card" id="devices">
    <h2>Devices (MAC/IP)</h2>
    <input type="text" id="deviceFilter" placeholder="Search Devices…">
    <table id="devicesTable"><thead><tr><th>MAC</th><th>Vendor</th><th>IPs</th><th>Packets</th></tr></thead><tbody></tbody></table>
  </div>
</div>

<!-- Chart.js -->
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<script>
  const summary = %SUMMARY%;
  const protocols = %PROTOCOLS%;
  const dns = %DNS%;
  const sni = %SNI%;
  const devices = %DEVICES%;
  const timeline = %TIMELINE%;

  // Summary metrics
  document.getElementById("packetCount").innerText = summary.processed_packets;
  document.getElementById("deviceCount").innerText = summary.device_count;
  const ts = summary.time_span_epoch;
  if (ts.first && ts.last) {
    let start = new Date(ts.first*1000).toISOString();
    let end = new Date(ts.last*1000).toISOString();
    document.getElementById("timeSpan").innerText = start.substr(11,8)+" → "+end.substr(11,8);
  }

  // Protocol chart
  new Chart(document.getElementById("protocolChart"), {
    type: 'pie',
    data: {
      labels: protocols.map(p => p[0]),
      datasets: [{
        data: protocols.map(p => parseInt(p[1])),
        backgroundColor: ['#2563eb','#f97316','#dc2626','#16a34a','#9333ea','#eab308','#06b6d4','#f43f5e']
      }]
    }
  });

  // Timeline chart
  new Chart(document.getElementById("timelineChart"), {
    type: 'line',
    data: {
      labels: timeline.map(t => new Date(t[0]*1000).toISOString().substr(11,8)),
      datasets: [{
        label: 'Packets/minute',
        data: timeline.map(t => parseInt(t[1])),
        borderColor: '#2563eb',
        backgroundColor: 'rgba(37,99,235,0.2)',
        fill: true,
        tension: 0.3
      }]
    }
  });

  // Fill tables
  function fillTable(tableId, rows) {
    const tbody = document.querySelector(`#${tableId} tbody`);
    rows.forEach(r => {
      const tr = document.createElement('tr');
      tr.innerHTML = `<td>${r[0]}</td><td>${r[1]}</td>`;
      tbody.appendChild(tr);
    });
  }
  fillTable("dnsTable", dns);
  fillTable("sniTable", sni);

  const devTbody = document.querySelector("#devicesTable tbody");
  devices.forEach(dev => {
    const tr = document.createElement('tr');
    tr.innerHTML = `<td>${dev.mac}</td><td>${dev.vendor}</td><td>${dev.ips}</td><td>${dev.pkts}</td>`;
    devTbody.appendChild(tr);
  });

  // Filters
  function setupFilter(inputId, tableId) {
    document.getElementById(inputId).addEventListener("keyup", function() {
      let filter = this.value.toLowerCase();
      let rows = document.querySelectorAll(`#${tableId} tbody tr`);
      rows.forEach(row => {
        row.style.display = row.innerText.toLowerCase().includes(filter) ? "" : "none";
      });
    });
  }
  setupFilter("dnsFilter","dnsTable");
  setupFilter("sniFilter","sniTable");
  setupFilter("deviceFilter","devicesTable");
</script>
</body>
</html>
"""

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-i", "--input", required=True, help="summary.json from pcap_metadata_report")
    ap.add_argument("-o", "--output", required=True, help="Output HTML file")
    args = ap.parse_args()

    with open(args.input, "r", encoding="utf-8") as f:
        summary = json.load(f)

    report_dir = os.path.dirname(args.input)
    def load_csv_rows(fname):
        rows = []
        path = os.path.join(report_dir, fname)
        if not os.path.exists(path): return rows
        with open(path, "r", encoding="utf-8") as f:
            next(f)  # skip header
            for line in f:
                parts = line.strip().split(",")
                if len(parts) > 1:
                    rows.append(parts)
        return rows

    protocols = load_csv_rows("protocols.csv")
    dns = load_csv_rows("dns_queries.csv")
    dns_counts = Counter([r[2] for r in dns])
    dns_top = dns_counts.most_common(15)

    sni = load_csv_rows("tls_sni.csv")
    sni_counts = Counter([r[3] for r in sni])
    sni_top = sni_counts.most_common(15)

    devices = load_csv_rows("devices.csv")
    device_objs = [{"mac": d[0], "vendor": d[1], "ips": d[2], "pkts": d[5]} for d in devices]

    timeline = load_csv_rows("timeline_minute.csv")
    timeline_points = [(int(r[0]), int(r[1])) for r in timeline]

    html = TEMPLATE.replace("%SUMMARY%", json.dumps(summary))
    html = html.replace("%PROTOCOLS%", json.dumps(protocols))
    html = html.replace("%DNS%", json.dumps(dns_top))
    html = html.replace("%SNI%", json.dumps(sni_top))
    html = html.replace("%DEVICES%", json.dumps(device_objs))
    html = html.replace("%TIMELINE%", json.dumps(timeline_points))

    with open(args.output, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"✅ Dashboard written to {args.output}")

if __name__ == "__main__":
    main()
