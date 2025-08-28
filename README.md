# 📊 MITM Capture → Metadata Report → Dashboard Guide (Kali Linux Lab)

This workflow demonstrates how to:

1. Run the **MITM lab script** (`mitm_solv2.py`) to intercept and capture traffic.
2. Process the capture file into structured metadata reports.
3. Build a **self-contained HTML dashboard** showing the attacker’s-eye view of the network.

---

## 🛠 Prerequisites

On your **Kali Linux VM**, install the dependencies:

```bash
# Keep system packages up to date
sudo apt update

# Core tools
sudo apt install -y nmap tcpdump dsniff tshark

# Python dependencies
sudo apt install -y python3-pandas python3-jinja2 python3-pyshark python3-manuf
```

(If needed: `python3 -m pip install --break-system-packages pyshark manuf pandas jinja2`)

---

## ⚡ Step 1 — Run MITM Capture Script

Start the MITM attack + capture:

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

➡️ Let it run long enough to collect traffic.
➡️ Stop it with `Ctrl+C`.
➡️ The file `mitm_capture.pcap` will be in your working directory.

---

## ⚡ Step 2 — Generate Metadata Reports

Convert the capture into structured reports:

```bash
python3 pcap_metadata_report.py -r mitm_capture.pcap -o ./report_out
```

This creates `./report_out/` with:

* `devices.csv` → MACs, vendors, IPs, packet counts
* `dns_queries.csv` → client IPs + queried domains
* `tls_sni.csv` → TLS hostnames (from Client Hello)
* `http_requests.csv` → plaintext HTTP requests (if any)
* `protocols.csv` → observed protocol counts
* `timeline_minute.csv` → packets per minute
* `summary.json` → aggregate metadata overview

---

## ⚡ Step 3 — Build HTML Dashboard

Generate the attacker-view dashboard:

```bash
python3 pcap_report_dashboard.py -i ./report_out/summary.json -o attacker_view.html
```

Open it directly in your Kali browser:

```bash
xdg-open attacker_view.html
```

---

## 📈 Dashboard Contents

* **Summary** → packets processed, time span, device count
* **Protocol Mix Pie Chart** → ARP, DNS, TLS, HTTP, etc.
* **Traffic Timeline Graph** → packet activity over time
* **Top DNS Queries** → most requested domains
* **Top TLS SNI Hostnames** → most visited services
* **Devices Table** → MACs, vendor inference, IPs, packet counts

> Blank sections simply mean no such traffic was present in the capture.

---

## 🎯 Example Workflow

1. Start MITM script:

   ```bash
   python3 mitm_solv2.py
   ```
2. Interact with the victim network (e.g., browsing).
3. Stop with `Ctrl+C`.
4. Generate reports:

   ```bash
   python3 pcap_metadata_report.py -r mitm_capture.pcap -o ./report_out
   ```
5. Build dashboard:

   ```bash
   python3 pcap_report_dashboard.py -i ./report_out/summary.json -o attacker_view.html
   ```
6. Open the report:

   ```bash
   xdg-open attacker_view.html
   ```

---

## 🧑‍🏫 Teaching Use

* Shows that **encryption protects content**, but **metadata still leaks**:

  * Device vendors and roles (via MAC OUIs).
  * Services/domains used (via DNS + TLS SNI).
  * Behaviour patterns (via timelines).
* Demonstrates reconnaissance without breaking encryption.

---

⚠️ Only run this workflow in the authorized **Kali Linux lab environment**. Do not use on production or personal networks.

---

# Notes on how attacks can avoid detection.
---

## ☕ Public Wi-Fi Environment (Coffee Shop, Library, Hotspot)

In open networks such as cafés or libraries, attribution of malicious activity is inherently weak. Attackers can obscure their identity by using **randomized or spoofed MAC addresses** — replacing their hardware’s unique identifier with a temporary or false one — and by keeping their sessions **short-lived** to minimise exposure. Even if defenders detect unusual traffic in real time, these measures make it difficult to tie activity to a specific device once the attacker disconnects. Unless CCTV or hotspot account records are available, there is typically no reliable forensic path back to a home address or named individual. In practice, detection is possible while the attacker is present, but durable attribution after they leave is rarely achievable.

---

## 🏢 Corporate / Managed Organisational Environment

In enterprise networks, hiding is significantly more challenging. Infrastructure such as **Network Access Control (NAC)**, DHCP and authentication logs, and switch CAM tables tightly link each **IP and MAC address** to a physical port, access point, or user account. Even if an attacker spoofs or randomises their MAC, the intrusion still produces anomalous ARP activity, unusual traffic flows, and identifiable switch-port mappings that security teams can correlate in real time. Because these environments combine technical controls with physical monitoring (e.g. CCTV, badge access records), defenders can usually both **detect** man-in-the-middle behaviour as it occurs and **trace it back** to a specific machine or location afterwards. As such, persistent invisibility on a corporate LAN is rarely practical without compromising another host to act as the attacker’s proxy.
