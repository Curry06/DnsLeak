# DnsLeak
DNSLeak Detector — A real-time DNS leak detection tool that monitors outgoing DNS requests locally to identify potential privacy leaks. Designed for security researchers and ethical hackers, it provides live alerts and detailed analysis to help detect DNS leaks instantly

# 🔍 DNSLeak Detector

A real-time DNS leak detection tool that monitors outgoing DNS requests on a local system to identify potential privacy leaks. Built for ethical hackers, penetration testers, and privacy-conscious users, this tool helps you detect when your DNS queries are being sent outside of your intended VPN or secure DNS setup.

---

## 🚀 Features

- 🕵️ Real-time DNS leak monitoring
- 📡 Tracks DNS queries and matches them against expected DNS servers
- 🧠 Local system analysis without external dependencies
- 📦 Lightweight and easy to run in the background
- 📁 JSON logging and optional verbose terminal output
- ⚠️ Alerts when DNS traffic is routed through unintended servers

---

## 🛠️ Installation

### Requirements

- Python 3.7+
- Works on Linux and macOS (Windows support WIP)
- `scapy`, `dnspython`, and `psutil` libraries

### Clone the repository

    bash
    git clone https://github.com/yourusername/dnsleak-detector.git
    cd dnsleak-detector

Install dependencies 

    pip install -r requirements.txt

🧪 Usage

    python dnsleak.py


Optional flags

    --json : Output DNS logs to leaks.json

    --verbose : Show detailed DNS traffic in terminal

    --interface eth0 : Specify network interface (default auto-detects)

📊 Output Example

    [!] DNS Leak Detected
    Queried Domain: example.com
    Resolver IP: 192.168.1.1
    Timestamp: 2025-06-29 10:23:54

🧠 How It Works

    Captures DNS traffic (UDP/53) using raw socket or scapy

    Extracts resolver IP and compares it with your expected DNS server (e.g., 10.8.0.1 from your VPN)

    Flags any unexpected resolver as a DNS leak

    Stores logs in real-time for analysis or alerting

🔒 Use Cases

    Check if your VPN is leaking DNS queries

    Monitor DNS behavior during penetration testing

    Run in the background for continuous DNS auditing


🧩 To-Do / Coming Soon

    GUI version with real-time charts

    Email or Discord alert integration

    Windows compatibility

    Auto-detect known public DNS (Google, Cloudflare, ISP)

🙌 Credits

    Developed by Vedant  and the security community.
    Special thanks to open-source contributors and testers.
