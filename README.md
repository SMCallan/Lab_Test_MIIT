# 📊 MITM Capture → Metadata Report → Dashboard Guide (Kali Linux Lab)

This lab demonstrates how to:

1. Run the **MITM capture script** (`mitm_solv2.py`) to intercept and record traffic.
2. Process the capture file into structured metadata reports.
3. Build a **self-contained HTML dashboard** that presents the attacker’s-eye view of the network.

---

## 🛠 Prerequisites

On your **Kali Linux VM**, install the required dependencies:

```bash
# Update system packages
sudo apt update

# Core networking tools
sudo apt install -y nmap tcpdump dsniff tshark macchanger

# Python libraries
sudo apt install -y python3-pandas python3-jinja2 python3-pyshark python3-manuf
```

(If your Kali build doesn’t have packaged versions, you can fall back to:
`python3 -m pip install --break-system-packages pyshark manuf pandas jinja2`)

---

## ⚡ Step 1 — Run MITM Capture Script

Launch the attack + capture process:

```bash
python3 mitm_solv2.py
```

The script will:

* Enable IP forwarding (Linux only).
* Start ARP spoofing between victim and gateway.
* Launch `tcpdump` in the background, saving packets to:

  ```
  mitm_capture.pcap
  ```

➡️ Let it run long enough to capture meaningful traffic.
➡️ Stop it with `Ctrl+C`.
➡️ The file `mitm_capture.pcap` will appear in your working directory.

---

## ⚡ Step 2 — Generate Metadata Reports

Transform the capture into structured reports:

```bash
python3 pcap_metadata_report.py -r mitm_capture.pcap -o ./report_out
```

This creates `./report_out/` containing:

* `devices.csv` → MACs, vendors, IPs, packet counts
* `dns_queries.csv` → client IPs + queried domains
* `tls_sni.csv` → TLS hostnames (from Client Hello)
* `http_requests.csv` → plaintext HTTP requests (if present)
* `protocols.csv` → observed protocol counts
* `timeline_minute.csv` → packet counts per minute
* `summary.json` → aggregate overview

---

## ⚡ Step 3 — Build HTML Dashboard

Generate the dashboard:

```bash
python3 pcap_report_dashboard.py -i ./report_out/summary.json -o attacker_view.html
```

Open directly in Kali:

```bash
xdg-open attacker_view.html
```

---

## 📈 Dashboard Contents

* **Summary** → packets processed, capture window, device count
* **Protocol Mix Pie Chart** → ARP, DNS, TLS, HTTP, etc.
* **Timeline Graph** → packet activity over time
* **Top DNS Queries** → most requested domains
* **Top TLS SNI Hostnames** → most visited services
* **Devices Table** → MACs, vendor inference, IPs, packet counts

> Blank sections = no such traffic in the capture.

---

## 🎯 Example Workflow

1. Start MITM script:

   ```bash
   python3 mitm_solv2.py
   ```
2. Interact with the victim network (e.g. web browsing).
3. Stop capture with `Ctrl+C`.
4. Generate reports:

   ```bash
   python3 pcap_metadata_report.py -r mitm_capture.pcap -o ./report_out
   ```
5. Build dashboard:

   ```bash
   python3 pcap_report_dashboard.py -i ./report_out/summary.json -o attacker_view.html
   ```
6. Open in browser:

   ```bash
   xdg-open attacker_view.html
   ```

---

## 🧑‍🏫 Teaching Use

* Demonstrates that **encryption protects content**, but **metadata still leaks**:

  * Device vendors and roles (via MAC OUIs).
  * Services/domains in use (via DNS + TLS SNI).
  * Behaviour patterns (via timelines).
* Shows how reconnaissance is possible **without decryption**.

⚠️ Only run this workflow in the authorized **Kali Linux lab environment**. Never on production or personal networks.

---

## ☕ Public Wi-Fi Environments

* Attackers often randomize/spoof MAC addresses.
* Sessions are kept short to reduce exposure.
* Detection is possible live, but attribution after disconnect is very difficult.

---

## 🏢 Corporate / Managed Networks

* Infrastructure (NAC, DHCP logs, switch CAM tables) links IPs/MACs to users/ports.
* Spoofing triggers anomalies (ARP conflicts, unusual flows).
* With physical monitoring, defenders can **detect and trace** MITM attempts in real time.

---

## 🎭 MAC Address Lab (Optional Extension)

**Tools:**

* `macchanger` (already installed).

**Check your current MAC:**

```bash
ip link show eth0
```

**Set a chosen MAC:**

```bash
sudo ip link set dev eth0 address de:ad:be:ef:00:01
```

**Randomize:**

```bash
sudo macchanger -r eth0
```

**Restore hardware MAC:**

```bash
sudo macchanger -p eth0
```

> Spoofing = targeted disguise. Randomizing = disposable identity. Each leaves a trail; neither makes you invisible.

---

## 👮 Blue Team Counterpoints

* **Collisions in ARP tables** → signal spoofing.
* **Locally administered MACs** → often randomized.
* **DHCP/NAC logs + switch tables** → map forged MACs to real ports.
* **Physical surveillance (CCTV, badges)** → ties network events to individuals.

In corporate networks, invisibility is rare. On public Wi-Fi, slipperiness depends on catching the attacker live.

