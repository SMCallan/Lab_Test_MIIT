# Lab_Test_MIIT
An exemplar for MIIT workflow.

---

# 📊 PCAP Metadata Report + Dashboard Guide

This toolkit gives you an **attacker’s-eye view** of network captures.
From any `.pcap` (Wireshark/tcpdump), it extracts **metadata** — devices, DNS queries, TLS SNI hostnames, HTTP requests — and builds a **self-contained HTML dashboard**.

---

## 🛠 Requirements

* Python **3.9+**
* `tshark` (part of Wireshark)

  * Linux (Debian/Ubuntu/Kali):

    ```bash
    sudo apt update && sudo apt install tshark -y
    ```
  * macOS (Homebrew):

    ```bash
    brew install wireshark
    ```
* Python dependencies:

  ```bash
  pip install pyshark manuf
  ```

---

## ⚡ Step 1 — Generate Metadata Reports

Run the metadata extractor on your `.pcap` file:

```bash
python3 pcap_metadata_report.py -r mitm_capture.pcap -o ./report_out
```

This creates a folder (`./report_out`) containing:

* `devices.csv` → MAC, vendor, IPs seen, first/last seen, packet count
* `dns_queries.csv` → time, client IP, query, type
* `tls_sni.csv` → time, src, dst, hostname (SNI from TLS Client Hello)
* `http_requests.csv` → time, src, host, method, URI, UA, auth header flag
* `protocols.csv` → protocol counts (how many packets per protocol)
* `timeline_minute.csv` → packets per minute (for charting)
* `summary.json` → quick aggregate summary (top DNS/SNI/HTTP, devices, capture span)

### Options

* Limit packets processed (for large captures):

  ```bash
  python3 pcap_metadata_report.py -r capture.pcap -o ./report_out --limit 50000
  ```
* Skip deeper parsing for speed:

  ```bash
  python3 pcap_metadata_report.py -r capture.pcap -o ./report_out --no-http --no-tls --no-dns
  ```

---

## ⚡ Step 2 — Generate the HTML Dashboard

Once reports exist, run the dashboard generator:

```bash
python3 pcap_report_dashboard.py -i ./report_out/summary.json -o ./attacker_view.html
```

This produces a **single self-contained HTML file** (`attacker_view.html`).
Open it in your browser — no server required.

---

## 📈 What You’ll See

* **Summary block** → input file, capture window, devices, top queries
* **Protocol Mix Pie Chart** → relative share of ARP, DNS, TLS, HTTP, etc.
* **Timeline Graph** → packet volume per minute
* **Top DNS Queries Table** → most requested domains
* **Top TLS SNI Table** → most contacted TLS hostnames
* **Devices Table** → MAC + vendor + IPs seen + packet counts

---

## 🎯 Example Workflow

1. Capture traffic in your lab with `tcpdump` or Wireshark:

   ```bash
   sudo tcpdump -i eth0 -w mitm_capture.pcap
   ```
2. Run the report maker:

   ```bash
   python3 pcap_metadata_report.py -r mitm_capture.pcap -o ./report_out
   ```
3. Build the dashboard:

   ```bash
   python3 pcap_report_dashboard.py -i ./report_out/summary.json -o attacker_view.html
   ```
4. Open `attacker_view.html` → browse the attacker’s view of your network.

---

## 🧑‍🏫 Teaching Use

* Show how **metadata alone** (DNS, SNI, MAC vendors) can profile a network.
* Demonstrate device/vendor fingerprinting (IoT vs laptops vs phones).
* Contrast plaintext vs encrypted traffic — HTTP vs HTTPS.
* Encourage defenders to reduce metadata leakage (DNS over HTTPS, segmentation).

---

⚠️ **Note:** Only run this in your **authorized training environment**.
Even without payloads, metadata can expose sensitive information.

---

