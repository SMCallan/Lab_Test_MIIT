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
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <style>
    :root {
      --bg: #f4f6f8;
      --card: #ffffff;
      --ink: #333333;
      --muted: #555555;
      --accent: #2563eb;
      --soft: #f1f5f9;
      --border: #e5e7eb;
    }
    * { box-sizing: border-box; }
    body { font-family: 'Segoe UI', Arial, sans-serif; margin: 0; background: var(--bg); color: var(--ink); }
    header {
      background: #1e293b; color: #fff; padding: 0.9em 1.25em;
      position: sticky; top: 0; z-index: 100; display:flex; align-items:center; justify-content:space-between;
    }
    header h1 { margin: 0; font-size: 1.05em; letter-spacing: .3px; }
    nav a { color: #fff; margin-left: .9em; text-decoration: none; font-size: .9em; opacity:.9 }
    nav a:hover { opacity: 1 }
    .container { max-width: 1200px; margin: 1.5em auto 2.5em; padding: 0 1em; }
    .card {
      background: var(--card); padding: 1.25em; margin-bottom: 1.5em;
      border-radius: 12px; box-shadow: 0 6px 18px rgba(10,20,40,.06), 0 1px 2px rgba(0,0,0,.04);
    }
    h2 { border-bottom: 2px solid var(--border); padding-bottom: .4em; margin: .1em 0 0.8em; font-size: 1.05em; }
    table { width: 100%; border-collapse: collapse; margin-top: 0.75em; }
    th, td { padding: 10px 12px; border-bottom: 1px solid var(--border); font-size: .95em; }
    th {
      background: #f9fafb; text-align: left; position: sticky; top: 60px; z-index: 2;
      font-weight: 600; color: #111827;
    }
    tr:nth-child(even) { background: #fafafa; }
    input[type="text"] {
      padding: 10px 12px; margin-bottom: 0.6em; width: 100%;
      border: 1px solid var(--border); border-radius: 8px; font-size: .95em;
      outline: none;
    }
    input[type="text"]:focus { border-color: var(--accent); box-shadow: 0 0 0 3px rgba(37,99,235,.12); }
    .metrics { display: grid; grid-template-columns: repeat(5, minmax(160px,1fr)); gap: 12px; }
    .metric { background: var(--soft); border: 1px solid var(--border); border-radius: 10px; padding: 16px 14px; text-align: center; }
    .metric h3 { margin: 0; font-size: 1.25em; color:#111; }
    .metric p { margin: .35em 0 0; font-size: .85em; color: var(--muted); }
    .chart-wrap { width: 100%; overflow-x: auto; }
    canvas { max-width: 100%; height: 360px; }
    .muted { color: var(--muted); font-size: .9em; }
    @media (max-width: 980px) {
      th { top: 100px; }
      .metrics { grid-template-columns: repeat(2, minmax(160px,1fr)); }
    }
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
      <div class="metric"><h3 id="deviceCount">0</h3><p>Devices (unique MACs)</p></div>
      <div class="metric"><h3 id="uniqueIps">0</h3><p>Unique IPs</p></div>
      <div class="metric"><h3 id="durationHuman">—</h3><p>Duration</p></div>
      <div class="metric"><h3 id="timeSpan">—</h3><p>Capture Window (UTC)</p></div>
    </div>
    <p class="muted" id="timelineNote" style="margin-top:.8em;"></p>
  </div>

  <div class="card" id="protocols">
    <h2>Protocol Mix</h2>
    <div class="chart-wrap"><canvas id="protocolChart"></canvas></div>
    <input type="text" id="protoFilter" placeholder="Search protocols…">
    <table id="protocolTable">
      <thead><tr><th>Protocol</th><th>Packets</th></tr></thead>
      <tbody></tbody>
    </table>
  </div>

  <div class="card" id="timeline">
    <h2>Traffic Timeline</h2>
    <div class="chart-wrap"><canvas id="timelineChart"></canvas></div>
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

  // ---- Summary metrics
  document.getElementById("packetCount").innerText = summary.processed_packets ?? 0;
  document.getElementById("deviceCount").innerText = summary.device_count ?? 0;
  document.getElementById("uniqueIps").innerText = summary.unique_ip_count ?? 0;
  document.getElementById("durationHuman").innerText = summary.duration_human ?? "—";
  const ts = summary.time_span_epoch || {};
  if (ts.first && ts.last) {
    let start = new Date(ts.first*1000).toISOString();
    let end = new Date(ts.last*1000).toISOString();
    document.getElementById("timeSpan").innerText = start.substr(11,8)+" → "+end.substr(11,8);
  }
  const res = (summary.timeline_resolution || "minute");
  document.getElementById("timelineNote").innerText =
    "Timeline resolution: " + res + (res==="minute" ? " (default)" : "");

  // ---- Protocol chart (legend hidden to prevent overflow)
  new Chart(document.getElementById("protocolChart"), {
    type: 'pie',
    data: {
      labels: protocols.map(p => p[0]),
      datasets: [{
        data: protocols.map(p => parseInt(p[1])),
        backgroundColor: ['#2563eb','#f97316','#dc2626','#16a34a','#9333ea','#eab308','#06b6d4','#f43f5e','#60a5fa','#34d399','#a78bfa','#fb7185']
      }]
    },
    options: { plugins: { legend: { display: false } } }
  });

  // ---- Protocol table + filter
  const protoTbody = document.querySelector("#protocolTable tbody");
  function renderProtocolRows(rows) {
    protoTbody.innerHTML = '';
    rows.forEach(p => {
      const tr = document.createElement("tr");
      tr.innerHTML = `<td>${p[0]}</td><td>${p[1]}</td>`;
      protoTbody.appendChild(tr);
    });
  }
  renderProtocolRows(protocols);

  document.getElementById("protoFilter").addEventListener("keyup", function() {
    const f = this.value.toLowerCase();
    const filtered = protocols.filter(p => (p[0]+" "+p[1]).toLowerCase().includes(f));
    renderProtocolRows(filtered);
  });

  // ---- Timeline chart
  new Chart(document.getElementById("timelineChart"), {
    type: 'line',
    data: {
      labels: timeline.map(t => new Date(t[0]*1000).toISOString().substr(11,8)),
      datasets: [{
        label: 'Packets per ' + res,
        data: timeline.map(t => parseInt(t[1])),
        borderColor: '#2563eb',
        backgroundColor: 'rgba(37,99,235,0.2)',
        fill: true,
        tension: 0.3,
        pointRadius: 0
      }]
    },
    options: {
      scales: { x: { ticks: { maxRotation: 0, autoSkip: true } } },
      plugins: { legend: { display: true } }
    }
  });

  // ---- DNS/SNI tables
  function fillTable(tableId, rows) {
    const tbody = document.querySelector(`#${tableId} tbody`);
    tbody.innerHTML = '';
    rows.forEach(r => {
      const tr = document.createElement('tr');
      tr.innerHTML = `<td>${r[0]}</td><td>${r[1]}</td>`;
      tbody.appendChild(tr);
    });
  }
  fillTable("dnsTable", dns);
  fillTable("sniTable", sni);

  // ---- Devices table
  const devTbody = document.querySelector("#devicesTable tbody");
  devTbody.innerHTML = '';
  devices.forEach(dev => {
    const tr = document.createElement('tr');
    tr.innerHTML = `<td>${dev.mac}</td><td>${dev.vendor}</td><td>${dev.ips}</td><td>${dev.pkts}</td>`;
    devTbody.appendChild(tr);
  });

  // ---- Filters for other tables
  function setupFilter(inputId, tableId) {
    const input = document.getElementById(inputId);
    input.addEventListener("keyup", function() {
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
        if not os.path.exists(path):
            return rows
        with open(path, "r", encoding="utf-8") as f:
            try:
                next(f)  # skip header
            except StopIteration:
                return rows
            for line in f:
                parts = line.rstrip("\n").split(",")
                if len(parts) > 1:
                    rows.append(parts)
        return rows

    # Base CSVs
    protocols = load_csv_rows("protocols.csv")
    dns = load_csv_rows("dns_queries.csv")
    dns_counts = Counter([r[2] for r in dns])
    dns_top = dns_counts.most_common(15)

    sni = load_csv_rows("tls_sni.csv")
    sni_counts = Counter([r[3] for r in sni])
    sni_top = sni_counts.most_common(15)

    devices = load_csv_rows("devices.csv")
    device_objs = [{"mac": d[0], "vendor": d[1], "ips": d[2], "pkts": d[5]} for d in devices]

    # Dynamic timeline loading per summary.timeline_resolution (fallbacks)
    res = (summary.get("timeline_resolution") or "minute").lower()
    timeline_candidates = [f"timeline_{res}.csv", "timeline_minute.csv", "timeline_second.csv", "timeline_hour.csv"]
    timeline_points = []
    for fname in timeline_candidates:
        data = load_csv_rows(fname)
        if data:
            try:
                timeline_points = [(int(r[0]), int(r[1])) for r in data]
            except Exception:
                timeline_points = []
            break

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
