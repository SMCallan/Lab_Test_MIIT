# 📊 MITM Capture → Metadata Report → Dashboard Guide (Kali Linux Lab)

This workflow shows how to:

1. Run the **MITM lab script** (`mitm_solv2.py`) to intercept and capture traffic.
2. Process the capture file into structured metadata reports.
3. Build a **self-contained HTML dashboard** showing the attacker’s-eye view.

---

## 🛠 Prerequisites

On your Kali Linux VM, install the dependencies:

```bash
# Ensure system packages are up to date
sudo apt update

# Required tools
sudo apt install -y nmap tcpdump dsniff tshark

# Python dependencies
sudo apt-get update
sudo apt-get install -y python3-pandas python3-jinja2 python3-pyshark python3-manuf
```

---

## ⚡ Step 1 — Run MITM Lab Script

Start the MITM attack + capture script:

```bash
python3 mitm_solv2.py
```

This script will:

* Enable IP forwarding (Linux only).
* Start ARP spoofing between the victim and the gateway.
* Launch `tcpdump` in the background, writing packets to:

  ```
  mitm_capture.pcap
  ```

Let it run long enough to collect traffic, then stop it with `Ctrl+C`.
The capture file `mitm_capture.pcap` will now be available in your working directory.

---

## ⚡ Step 2 — Generate Metadata Reports

Process the capture into structured CSV + JSON reports:

```bash
python3 pcap_metadata_report.py -r mitm_capture.pcap -o ./report_out
```

This creates `./report_out/` with:

* `devices.csv` → MAC, vendor, IPs seen, packet counts
* `dns_queries.csv` → client IPs + domains queried
* `tls_sni.csv` → TLS hostnames from Client Hello
* `http_requests.csv` → plaintext HTTP requests (if any)
* `protocols.csv` → counts of observed protocols
* `timeline_minute.csv` → packets per minute
* `summary.json` → aggregate metadata overview

---

## ⚡ Step 3 — Build HTML Dashboard

Generate a single-file HTML dashboard:

```bash
python3 pcap_report_dashboard.py -i ./report_out/summary.json -o attacker_view.html
```

Open `attacker_view.html` in your Kali browser.

---

## 📈 Dashboard Contents

* **Summary block** → capture window, device count, packet totals
* **Protocol Mix Pie Chart** → ARP, DNS, TLS, HTTP, etc.
* **Traffic Timeline Graph** → packet activity over time
* **Top DNS Queries** → most requested domains
* **Top TLS SNI Hostnames** → most visited services (even if encrypted)
* **Devices Table** → MAC addresses, vendor inference, IPs seen

---

## 🎯 Example Workflow

1. Run MITM script:

   ```bash
   python3 mitm_solv2.py
   ```
2. Stop it with `Ctrl+C` → leaves `mitm_capture.pcap`.
3. Generate reports:

   ```bash
   python3 pcap_metadata_report.py -r mitm_capture.pcap -o ./report_out
   ```
4. Build dashboard:

   ```bash
   python3 pcap_report_dashboard.py -i ./report_out/summary.json -o attacker_view.html
   ```
5. Open `attacker_view.html` → explore the attacker’s-eye metadata.

---

## 🧑‍🏫 Teaching Use

* Demonstrates that **encryption protects content**, but **metadata still leaks**:

  * Device vendors and roles (via MAC OUIs).
  * Services/domains used (via DNS + TLS SNI).
  * Behaviour patterns (via timelines).
* Shows attackers can profile a network without breaking encryption.

---

⚠️ Only run this workflow in the authorized Kali Linux lab environment. Do not use on production or personal networks.

---
