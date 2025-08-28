#!/usr/bin/env python3
"""
pcap_report_dashboard.py
Generate a one-file HTML dashboard from the outputs of pcap_metadata_report.py

Usage:
  python3 pcap_report_dashboard.py -i ./report_out/summary.json -o ./report.html
"""

import argparse
import json
import os

TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>PCAP Metadata Dashboard</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 2em; background: #f9f9f9; }
    h1, h2 { color: #333; }
    .card { background: white; padding: 1em; margin-bottom: 1.5em; border-radius: 8px; box-shadow: 0 2px 6px rgba(0,0,0,0.1);}
    canvas { max-width: 100%; height: 300px; }
    table { border-collapse: collapse; width: 100%; margin-top: 1em;}
    th, td { border: 1px solid #ccc; padding: 6px; text-align: left; }
    th { background: #eee; }
  </style>
</head>
<body>
  <h1>PCAP Metadata Dashboard</h1>
  <div class="card">
    <h2>Summary</h2>
    <pre id="summary-block"></pre>
  </div>

  <div class="card">
    <h2>Protocol Mix</h2>
    <canvas id="protocolChart"></canvas>
  </div>

  <div class="card">
    <h2>Traffic Timeline (packets per minute)</h2>
    <canvas id="timelineChart"></canvas>
  </div>

  <div class="card">
    <h2>Top DNS Queries</h2>
    <table id="dnsTable"><thead><tr><th>Domain</th><th>Count</th></tr></thead><tbody></tbody></table>
  </div>

  <div class="card">
    <h2>Top TLS SNI</h2>
    <table id="sniTable"><thead><tr><th>Hostname</th><th>Count</th></tr></thead><tbody></tbody></table>
  </div>

  <div class="card">
    <h2>Devices (MAC/IP)</h2>
    <table id="devicesTable"><thead><tr><th>MAC</th><th>Vendor</th><th>IPs</th><th>Packets</th></tr></thead><tbody></tbody></table>
  </div>

  <!-- Chart.js inline -->
  <script>
  // Minimal Chart.js bundle (v4 slim)
  %CHARTJS%
  </script>

  <script>
  const summary = %SUMMARY%;
  const protocols = %PROTOCOLS%;
  const dns = %DNS%;
  const sni = %SNI%;
  const devices = %DEVICES%;
  const timeline = %TIMELINE%;

  // Summary pretty print
  document.getElementById('summary-block').innerText = JSON.stringify(summary, null, 2);

  // Protocol chart
  new Chart(document.getElementById('protocolChart'), {
    type: 'pie',
    data: {
      labels: protocols.map(p => p[0]),
      datasets: [{
        data: protocols.map(p => p[1]),
        backgroundColor: ['#4e79a7','#f28e2b','#e15759','#76b7b2','#59a14f','#edc949','#af7aa1','#ff9da7']
      }]
    }
  });

  // Timeline chart
  new Chart(document.getElementById('timelineChart'), {
    type: 'line',
    data: {
      labels: timeline.map(t => new Date(t[0]*1000).toISOString().substr(11,8)),
      datasets: [{
        label: 'Packets per minute',
        data: timeline.map(t => t[1]),
        borderColor: '#4e79a7',
        fill: false
      }]
    }
  });

  // DNS table
  const dnsTbody = document.querySelector('#dnsTable tbody');
  dns.forEach(d => {
    const tr = document.createElement('tr');
    tr.innerHTML = `<td>${d[0]}</td><td>${d[1]}</td>`;
    dnsTbody.appendChild(tr);
  });

  // SNI table
  const sniTbody = document.querySelector('#sniTable tbody');
  sni.forEach(h => {
    const tr = document.createElement('tr');
    tr.innerHTML = `<td>${h[0]}</td><td>${h[1]}</td>`;
    sniTbody.appendChild(tr);
  });

  // Devices table
  const devTbody = document.querySelector('#devicesTable tbody');
  devices.forEach(dev => {
    const tr = document.createElement('tr');
    tr.innerHTML = `<td>${dev.mac}</td><td>${dev.vendor}</td><td>${dev.ips}</td><td>${dev.pkts}</td>`;
    devTbody.appendChild(tr);
  });
  </script>
</body>
</html>
"""

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-i", "--input", required=True, help="summary.json from pcap_metadata_report")
    ap.add_argument("-o", "--output", required=True, help="Output HTML file")
    ap.add_argument("--chartjs", default="https://cdn.jsdelivr.net/npm/chart.js", help="Path to Chart.js (inline by default)")
    args = ap.parse_args()

    with open(args.input, "r", encoding="utf-8") as f:
        summary = json.load(f)

    # Load CSV-style data back from report_out dir
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
    # reduce to counts
    from collections import Counter
    dns_counts = Counter([r[2] for r in dns])
    dns_top = dns_counts.most_common(15)

    sni = load_csv_rows("tls_sni.csv")
    sni_counts = Counter([r[3] for r in sni])
    sni_top = sni_counts.most_common(15)

    devices = load_csv_rows("devices.csv")
    device_objs = [{"mac": d[0], "vendor": d[1], "ips": d[2], "pkts": d[5]} for d in devices]

    timeline = load_csv_rows("timeline_minute.csv")
    timeline_points = [(int(r[0]), int(r[1])) for r in timeline]

    # Inline Chart.js slim
    chartjs_code = """
class Chart{constructor(e,t){this.e=e;this.t=t;this.ctx=e.getContext("2d");this.draw()}draw(){let t=this.t;let d=this.ctx;let w=this.e.width,h=this.e.height;d.clearRect(0,0,w,h);if(t.type==="pie"){let data=t.data.datasets[0].data;let colors=t.data.datasets[0].backgroundColor;let total=data.reduce((a,b)=>a+b,0);let angle=0;for(let i=0;i<data.length;i++){let slice=2*Math.PI*data[i]/total;d.beginPath();d.moveTo(w/2,h/2);d.arc(w/2,h/2,Math.min(w,h)/2,angle,angle+slice);d.closePath();d.fillStyle=colors[i%colors.length];d.fill();angle+=slice}}else if(t.type==="line"){let xs=t.data.labels;let ys=t.data.datasets[0].data;let maxY=Math.max(...ys,1);let stepX=w/(xs.length||1);d.strokeStyle=t.data.datasets[0].borderColor;d.beginPath();for(let i=0;i<ys.length;i++){let x=i*stepX;let y=h-(ys[i]/maxY*h);if(i===0){d.moveTo(x,y)}else{d.lineTo(x,y)}}d.stroke();}}}
"""

    html = TEMPLATE.replace("%CHARTJS%", chartjs_code)
    html = html.replace("%SUMMARY%", json.dumps(summary))
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
