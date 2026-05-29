"""
Network Security Analyzer (Network Sentinel)
Developed by: lordradez
Description: Real-time packet capture, analysis, and visualization tool.
"""
from scapy.all import sniff, IP, TCP, UDP
from collections import defaultdict
import pandas as pd
import time
import matplotlib.pyplot as plt

# -------------------- CONFIG --------------------
CAPTURE_COUNT = 100
DOS_THRESHOLD = 50
SUSPICIOUS_PORTS = {21, 23, 3389}  # FTP, Telnet, RDP
LOG_FILE = "alerts.log"
CSV_FILE = "network_report.csv"

# -------------------- DATA STRUCTURES --------------------
ip_counter = defaultdict(int)
packet_data = []

# -------------------- LOGGING FUNCTION --------------------
def log_alert(message):
    with open(LOG_FILE, "a") as f:
        f.write(f"{time.ctime()} - {message}\n")

# -------------------- PACKET PROCESSING --------------------
def process_packet(packet):
    if packet.haslayer(IP):
        src = packet[IP].src
        dst = packet[IP].dst
        proto = packet[IP].proto
        sport = None
        dport = None
        alert = ""

        # TCP packet
        if packet.haslayer(TCP):
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            if dport in SUSPICIOUS_PORTS:
                alert = f"[ALERT] Suspicious TCP port: {src} -> {dst}:{dport}"
                print(alert)
                log_alert(alert)

        # UDP packet
        elif packet.haslayer(UDP):
            sport = packet[UDP].sport
            dport = packet[UDP].dport
            if dport in SUSPICIOUS_PORTS:
                alert = f"[ALERT] Suspicious UDP port: {src} -> {dst}:{dport}"
                print(alert)
                log_alert(alert)

        # DoS detection
        ip_counter[src] += 1
        if ip_counter[src] > DOS_THRESHOLD:
            alert = f"[ALERT] Possible DoS attack from {src} (Packets: {ip_counter[src]})"
            print(alert)
            log_alert(alert)

        # Print packet info
        info = f"{time.ctime()} | {src} -> {dst} | Protocol: {proto} | Sport: {sport} | Dport: {dport}"
        print(info)

        # Save packet info
        packet_data.append({
            "Timestamp": time.ctime(),
            "Source": src,
            "Destination": dst,
            "Protocol": proto,
            "Source Port": sport,
            "Destination Port": dport,
            "Alert": alert
        })

# -------------------- CAPTURE --------------------
def get_default_interface():
    try:
        from scapy.all import conf
        return conf.iface
    except:
        return None

target_iface = get_default_interface()
print(f"Capturing packets on interface: {target_iface}")
print("Detection (DoS and Suspicious Ports) active. Logging to alerts.log...")

sniff(
    iface=target_iface,
    count=CAPTURE_COUNT,
    prn=process_packet
)

# -------------------- SAVE CSV --------------------
df = pd.DataFrame(packet_data)
df.to_csv(CSV_FILE, index=False)
print(f"\nCSV report saved as {CSV_FILE}")

# -------------------- SUMMARY --------------------
print("\n---- SUMMARY STATISTICS ----")
total_packets = len(packet_data)
tcp_packets = sum(1 for p in packet_data if p["Protocol"] == 6)
udp_packets = sum(1 for p in packet_data if p["Protocol"] == 17)
top_talkers = sorted(ip_counter.items(), key=lambda x: x[1], reverse=True)[:5]

print(f"Total Packets Captured: {total_packets}")
print(f"TCP Packets: {tcp_packets}, UDP Packets: {udp_packets}")
print("Top 5 Source IPs by Packet Count:")
for ip, count in top_talkers:
    print(f"{ip}: {count} packets")

# -------------------- VISUALIZATION --------------------
plt.figure(figsize=(10,5))

# TCP vs UDP Bar Chart
plt.subplot(1,2,1)
plt.bar(['TCP','UDP'], [tcp_packets, udp_packets], color=['blue','green'])
plt.title('TCP vs UDP Packets')
plt.ylabel('Number of Packets')

# Top 5 talkers Bar Chart
plt.subplot(1,2,2)
ips = [ip for ip,_ in top_talkers]
counts = [count for _,count in top_talkers]
plt.bar(ips, counts, color='red')
plt.title('Top 5 Source IPs')
plt.ylabel('Packet Count')
plt.xticks(rotation=45)

plt.tight_layout()
plt.show()