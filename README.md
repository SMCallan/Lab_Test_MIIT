# Lab_Test_MIIT
An exemplar for a MIIT scripting on linux + wireshark analyzer to build attacker view reports.



How to use : pcap_metadata_report.py
Install dependencies
# macOS or Linux
brew install wireshark || true    # macOS (adds tshark)
# or: sudo apt install tshark     # Debian/Ubuntu/Kali
pip install pyshark manuf
Run on a capture
python3 pcap_metadata_report.py -r mitm_capture.pcap -o ./report_out
# Optional (faster): skip deep parsing where not needed
python3 pcap_metadata_report.py -r mitm_capture.pcap -o ./report_out --no-http --no-tls
Open the outputs
report_out/summary.json → quick, human-readable overview
devices.csv → MAC ⇄ vendor, IPs, first/last seen
dns_queries.csv / tls_sni.csv / http_requests.csv → per-event metadata
protocols.csv → your protocol mix
timeline_minute.csv → packets per minute (easy to chart)
