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

---

# 🕶️ Lab Manual: Bending Your Digital Fingerprints

> “Your MAC is your fingerprint on the wire. Change the fingerprint, and you walk the net in disguise.”

In this lab you’ll learn how to mess with the one thing most networks assume is sacred: the **MAC address**. You’ll see how to swap it, randomize it, and confuse anyone watching the wire.

⚠️ **Reality check:** This is a **controlled exercise**. Do not take these skills outside your lab. On real corporate or public networks, this behaviour is both illegal and noisy. In here though, we play with the gloves off.

---

## 🛠 Setup

* You’re running **Kali Linux** inside a VM (VirtualBox or UTM).
* **Networking mode:** make sure the VM is in **Bridged Mode**.

  * NAT mode hides your spoofing — the world just sees your host Mac’s real address.
  * Bridged mode lets your VM stand on its own two feet, with its own MAC visible to the LAN. That’s where the fun is.

---

## 🔍 Step 1 — Spot your current fingerprint

```bash
ip link show
```

Find your NIC (`eth0`, maybe `ens33`, or `wlan0` if using a USB Wi-Fi adapter).
You’ll see something like:

```
link/ether 08:00:27:12:34:56
```

That’s your default MAC. The cage you’re about to break out of.

---

## 🎭 Step 2 — Spoof it

Take your interface down, switch identities, and bring it back up:

```bash
sudo ip link set dev eth0 down
sudo ip link set dev eth0 address de:ad:be:ef:00:01
sudo ip link set dev eth0 up
```

Check the new mask:

```bash
ip link show eth0
```

Congrats — you’re no longer you. To the LAN, you’re some other machine entirely.

---

## 🎲 Step 3 — Randomize it

Install **macchanger**, the little chaos tool:

```bash
sudo apt install macchanger
```

* Show your current state:

  ```bash
  sudo macchanger -s eth0
  ```
* Flip to a totally random MAC:

  ```bash
  sudo macchanger -r eth0
  ```
* Or scramble while keeping the same vendor prefix (sneakier):

  ```bash
  sudo macchanger -a eth0
  ```

Every time you reconnect, you can wear a new mask.

---

## ⚖️ Spoofing vs. Randomizing — Which Mask Do You Wear?

Here’s the deal: you don’t stack both — you **choose depending on the mission**.

* **Spoofing (manual pick):**
  You control the disguise. Want to look like a Dell laptop or an iPhone? Spoof their vendor prefix.

  * 💡 Best for **blending in** on a network that expects specific device types.
  * ⚠️ High risk: if the real device with that MAC is present, you collide and draw heat.

* **Randomizing (auto):**
  You let chaos hand you an identity. Every session is disposable.

  * 💡 Best for **public Wi-Fi privacy**, where you just don’t want to be tracked across logins.
  * ⚠️ In enterprise LANs, randomized MACs stand out because they carry the “locally administered” flag. Blue Teams notice.

* **Short-lived sessions:** Always a good practice. Time is heat. The longer you linger, the easier you are to burn.

👉 Rule of thumb:

* Public café Wi-Fi? **Randomize**.
* Corporate LAN lab? **Spoof** to look like a known vendor.

---

## ⏳ Step 4 — Keep it short

In the underground, **time is heat**. The longer you sit, the easier you are to find.
A **short-lived session** is just that: connect, do your thing, disconnect.
Minutes, not hours. Pop in like a ghost, vanish before the blue team blinks.

---

## 🧹 Step 5 — Clean up

When you’re done, restore your original face:

```bash
sudo macchanger -p eth0
```

or manually reset the hardware MAC you noted earlier.

---

## 💡 Reflection

* Spoofing = targeted disguise, useful if you want to look like someone specific.
* Randomizing = throwaway masks, best for avoiding long-term tracking.
* Neither makes you invisible; they just change the shape of your shadow.

---

## ⚔️ Blue Team Reality Check

Even in disguise, defenders have tricks: ARP tables, switch logs, RF triangulation. A fake MAC hides your hardware ID — it doesn’t make you invisible. In a corporate LAN, you’d still get pinned down. On public Wi-Fi, you’d need cameras or login records to get truly burned.

---

> “In the lab, we learn the shadows. Outside the lab, respect the light.”

---

# 👮‍♂️ The Hunter’s Guide: Spotting the Masked Ones

> *“I am the Law. The network is my city. Every packet is under my jurisdiction. No disguise, no trick, no random mask escapes my gaze.”*

This is your doctrine for hunting those who would hide behind forged MACs and fleeting sessions.

---

## ⚖️ 1. Know the Law of the Wire

Every device walks the network with a **MAC address** — a digital badge. When it’s real, it matches vendor records. When it’s fake, the seams show: odd prefixes, collisions, sudden flips.

The attacker thinks it’s a mask. To you, it’s probable cause.

---

## 🔎 2. Signs of the Masked

* **Collisions in the ARP tables**
  Two machines shouting with the same MAC? One of them is a fraud.

* **Gratuitous ARP storms**
  A node keeps insisting “I am the gateway”? That’s ARP spoofing. Guilty on sight.

* **Locally administered MACs**
  Randomized addresses flip the “U/L” bit. They betray themselves as disposable masks.

* **Rapid identity churn**
  A device vanishes and reappears with a new face every few minutes. Real citizens don’t act like that. Criminals do.

---

## 🛠️ 3. Tools of Justice

* **arpwatch / Zeek / Suricata**
  Your eyes on ARP — they log every suspicious update, every conflict.

* **Switch CAM tables**
  The switch is your informant. It knows which port each MAC calls home.

* **DHCP and NAC logs**
  The registry of truth. Every lease, every login. A spoof still leaves footprints here.

* **CCTV and access records**
  Physical and digital law meet. The badge scan on the door, the camera above the desk, tie the fake MAC back to flesh and blood.

---

## 🔥 4. Tracking the Guilty

* Spot the forged MAC.
* Query the switch: *“Which port carries this mask?”*
* Lock the port. Quarantine the device.
* Cross-reference with DHCP logs and building access.
* The mask comes off. The attacker stands revealed.

---

## ⚔️ 5. The Verdict

* **Public Wi-Fi villains:** Slippery. If you don’t catch them in the act, they fade into the crowd. But while they’re live, their RF signal gives them away.
* **Corporate intruders:** No escape. Every packet is logged, every port accounted for. If they sit on your LAN, you will find them.

> *“They can spoof. They can randomize. They can run. But they can’t hide from the Law of the Wire.”*
