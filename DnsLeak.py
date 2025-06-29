# dnsleak_advanced.py (CLI-based advanced DNS leak detector)

import scapy.all as scapy
import socket
import json
import time
from datetime import datetime
from collections import defaultdict
import argparse

# Known public DNS providers
KNOWN_DNS = {
    "Google": ["8.8.8.8", "8.8.4.4"],
    "Cloudflare": ["1.1.1.1", "1.0.0.1"],
    "Quad9": ["9.9.9.9"],
    "OpenDNS": ["208.67.222.222", "208.67.220.220"],
    "CleanBrowsing": ["185.228.168.168"],
    "ProtonVPN": ["169.150.218.133", "169.150.218.134", "169.150.218.135", "169.150.218.136"]
}

# Common DoH IPs (partial list, non-exhaustive)
DOH_IPS = set(KNOWN_DNS["Google"] + KNOWN_DNS["Cloudflare"] + KNOWN_DNS["ProtonVPN"])

# Parser setup
parser = argparse.ArgumentParser(description="Advanced DNS Leak Detection Tool (CLI Mode)")
parser.add_argument("--log", default="leaks.json", help="File to log leak entries")
parser.add_argument("--test-mode", action="store_true", help="Run test DNS request to inject leak")
parser.add_argument("--trusted", nargs="+", default=["127.0.0.1"], help="Trusted DNS resolver IPs")
args = parser.parse_args()

TRUSTED_DNS = set(args.trusted)
LOG_FILE = args.log
SAFE_COUNT = 0
LEAK_COUNT = 0

recent_queries = defaultdict(float)
DEDUP_TTL = 10  # seconds

print("\n[*] Advanced DNS Leak Monitor Started (CLI Mode)")
print("--------------------------------------------------------------")
print(" Status |        Time        | Domain / Type       | Resolver")
print("--------|--------------------|----------------------|-----------")


def log_leak(entry):
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(entry) + "\n")


def classify_ip(ip):
    for provider, ips in KNOWN_DNS.items():
        if ip in ips:
            return provider
    return "Unknown"


def handle_query(domain, resolver_ip, proto="UDP"):
    global SAFE_COUNT, LEAK_COUNT
    now = time.time()
    key = (domain, resolver_ip, proto)

    # De-duplication
    if now - recent_queries[key] < DEDUP_TTL:
        return
    recent_queries[key] = now

    # Safe or Leak
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    provider = classify_ip(resolver_ip)
    status = "SAFE" if resolver_ip in TRUSTED_DNS else "LEAK"

    if status == "LEAK":
        LEAK_COUNT += 1
        print(f"\033[91m [LEAK] \033[0m| {timestamp} | {domain:<20} | {resolver_ip}")
    else:
        SAFE_COUNT += 1
        print(f"\033[92m [SAFE] \033[0m| {timestamp} | {domain:<20} | {resolver_ip}")

    log_leak({
        "status": status,
        "time": timestamp,
        "domain": domain,
        "resolver": resolver_ip,
        "provider": provider,
        "protocol": proto
    })


# Process packets from multiple protocols
def process_packet(packet):
    if packet.haslayer(scapy.DNSQR) and packet.haslayer(scapy.IP):
        domain = packet[scapy.DNSQR].qname.decode(errors="ignore").rstrip('.')
        resolver_ip = packet[scapy.IP].dst
        proto = "TCP" if packet.haslayer(scapy.TCP) else "UDP"
        handle_query(domain, resolver_ip, proto)


# Inject test DNS query
if args.test_mode:
    try:
        print("[*] Running test leak lookup to 'leaktest.dnsleaktest.com'...")
        socket.gethostbyname("leaktest.dnsleaktest.com")
        time.sleep(2)
    except Exception as e:
        print(f"[!] DNS test lookup failed: {e}")

# Start sniffing all relevant DNS-related traffic
try:
    scapy.sniff(filter="udp port 53 or tcp port 53 or tcp port 443 or tcp port 853", store=False, prn=process_packet)
except KeyboardInterrupt:
    print("\n[*] Stopping monitor...")
    print("--------------------------------------------------------------")
    print(f"\033[92mSAFE QUERIES :\033[0m {SAFE_COUNT}")
    print(f"\033[91mLEAKED QUERIES:\033[0m {LEAK_COUNT}")
    print("--------------------------------------------------------------")
