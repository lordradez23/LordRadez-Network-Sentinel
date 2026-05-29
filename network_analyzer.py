import sys

try:
    from scapy.all import sniff, IP, TCP, UDP, conf
except ImportError:
    print("Error: Scapy is not installed. Run 'pip install scapy'.")
    sys.exit(1)

try:
    import pandas as pd
except ImportError:
    print("Error: Pandas is not installed. Run 'pip install pandas'.")
    sys.exit(1)

try:
    import matplotlib.pyplot as plt
except ImportError:
    plt = None
    print("Shield: Matplotlib not found. Visualization will be skipped.")

from collections import defaultdict
import time

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
    try:
        with open(LOG_FILE, "a") as f:
            f.write(f"{time.ctime()} - {message}\n")
    except Exception as e:
        print(f"Logging Error: {e}")

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
def start_sniffing():
    try:
        # Detect interface
        target_iface = conf.iface
        print(f"Capturing packets on interface: {target_iface}")
        print("Detection (DoS and Suspicious Ports) active. Press Ctrl+C to stop early.")
        
        sniff(
            iface=target_iface,
            count=CAPTURE_COUNT,
            prn=process_packet
        )
    except PermissionError:
        print("\nERROR: Permission Denied. Please run as Administrator (Windows) or with sudo (Linux).")
        sys.exit(1)
    except Exception as e:
        print(f"\nERROR during packet capture: {e}")
        if "Npcap" in str(e) or "WinPcap" in str(e):
            print("Ensure Npcap is installed: https://npcap.com/")
        sys.exit(1)

start_sniffing()

# -------------------- SAVE CSV --------------------
if packet_data:
    df = pd.DataFrame(packet_data)
    df.to_csv(CSV_FILE, index=False)
    print(f"\nCSV report saved as {CSV_FILE}")
else:
    print("\nNo packets captured. Skipping CSV export.")

# -------------------- SUMMARY --------------------
print("\n---- SUMMARY STATISTICS ----")
total_packets = len(packet_data)
if total_packets > 0:
    tcp_packets = sum(1 for p in packet_data if p["Protocol"] == 6)
    udp_packets = sum(1 for p in packet_data if p["Protocol"] == 17)
    top_talkers = sorted(ip_counter.items(), key=lambda x: x[1], reverse=True)[:5]

    print(f"Total Packets Captured: {total_packets}")
    print(f"TCP Packets: {tcp_packets}, UDP Packets: {udp_packets}")
    print("Top 5 Source IPs by Packet Count:")
    for ip, count in top_talkers:
        print(f"{ip}: {count} packets")

    # -------------------- VISUALIZATION --------------------
    if plt and total_packets > 0:
        try:
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
        except Exception as e:
            print(f"Visualization Error: {e}")
else:
    print("No data captured to display statistics.")