"""
LordRadez-Network-Sentinel
Developed by: lordradez
Description: Professional real-time network intelligence and security monitoring tool.
"""

import sys
import time
import logging
import argparse
from collections import defaultdict
from typing import Any, Dict, List, Optional

# --- Dependency Check ---
try:
    from scapy.all import sniff, IP, TCP, UDP, conf
except ImportError:
    print("Error: Scapy is not installed. Run 'pip install scapy'.")
    sys.exit(1)

try:
    import pandas as pd
except ImportError:
    pd = None
    print("Warning: Pandas not found. CSV export will be disabled.")

try:
    import matplotlib.pyplot as plt
except ImportError:
    plt = None
    print("Warning: Matplotlib not found. Visualization will be disabled.")

# --- Configuration & Logging ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("alerts.log"),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("NetworkSentinel")

class NetworkSentinel:
    def __init__(self, capture_count: int = 100, dos_threshold: int = 50):
        self.capture_count = capture_count
        self.dos_threshold = dos_threshold
        self.suspicious_ports = {21, 23, 3389}  # FTP, Telnet, RDP
        self.ip_counter = defaultdict(int)
        self.packet_data: List[Dict[str, Any]] = []
        self.csv_file = "network_report.csv"

    def process_packet(self, packet: Any) -> None:
        """Heuristic analysis of incoming packets."""
        if not packet.haslayer(IP):
            return

        src = packet[IP].src
        dst = packet[IP].dst
        proto = packet[IP].proto
        sport = None
        dport = None
        alert_msg = ""

        # Port reconnaissance detection
        if packet.haslayer(TCP):
            sport, dport = packet[TCP].sport, packet[TCP].dport
            if dport in self.suspicious_ports:
                alert_msg = f"Suspicious TCP Access: {src} -> {dst}:{dport}"
        
        elif packet.haslayer(UDP):
            sport, dport = packet[UDP].sport, packet[UDP].dport
            if dport in self.suspicious_ports:
                alert_msg = f"Suspicious UDP Access: {src} -> {dst}:{dport}"

        if alert_msg:
            logger.warning(alert_msg)

        # DoS detection logic
        self.ip_counter[src] += 1
        if self.ip_counter[src] > self.dos_threshold:
            dos_msg = f"Potential DoS Attack: {src} ({self.ip_counter[src]} packets)"
            logger.critical(dos_msg)
            alert_msg = dos_msg if not alert_msg else f"{alert_msg} | {dos_msg}"

        # General logging
        logger.info(f"{src} -> {dst} | Proto: {proto} | Ports: {sport}->{dport}")

        self.packet_data.append({
            "Timestamp": time.ctime(),
            "Source": src,
            "Destination": dst,
            "Protocol": proto,
            "Source Port": sport,
            "Destination Port": dport,
            "Alert": alert_msg
        })

    def _simulate_packets(self) -> None:
        """Generates mock traffic for demonstration purposes."""
        logger.info("Entering Simulation Mode. Generating mock traffic...")
        mock_ips = ["192.168.1.10", "10.0.0.5", "172.16.0.22", "8.8.8.8"]
        
        for i in range(self.capture_count):
            # Simulate a normal packet or a threat
            src = mock_ips[i % len(mock_ips)]
            dst = "192.168.1.1"
            sport = 443
            dport = 80
            proto = 6 # TCP default
            
            # Artificial threat scenarios
            if i > 70: # Simulate a DoS from the first IP
                src = mock_ips[0]
            elif i % 15 == 0: # Simulate a suspicious port access
                dport = 21 # FTP
            
            # Create a mock object that mimics a Scapy packet
            class MockPacket:
                def __init__(self, s, d, sp, dp, pr):
                    self.layers = {
                        'IP': type('IP', (), {'src': s, 'dst': d, 'proto': pr}),
                        'TCP': type('TCP', (), {'sport': sp, 'dport': dp})
                    }
                def haslayer(self, cls):
                    return cls.__name__ in self.layers
                def __getitem__(self, cls):
                    return self.layers[cls.__name__]

            self.process_packet(MockPacket(src, dst, sport, dport, proto))
            time.sleep(0.05) # Realistic flow

    def start(self, simulate: bool = False) -> None:
        """Initialize packet sniffing or simulation."""
        if simulate:
            self._simulate_packets()
            return

        try:
            iface = conf.iface
            logger.info(f"Sentinel active on interface: {iface}")
            logger.info(f"Capturing {self.capture_count} packets. Press Ctrl+C to abort.")
            
            sniff(
                iface=iface,
                count=self.capture_count,
                prn=self.process_packet
            )
        except PermissionError:
            logger.error("Root/Admin privileges required for packet capture.")
            logger.info("Try running with --simulate to see a demo without privileges.")
            sys.exit(1)
        except Exception as e:
            logger.error(f"Capture Failure: {e}")
            if any(x in str(e) for x in ["Npcap", "WinPcap"]):
                logger.info("Tip: Install Npcap from https://npcap.com/")
            logger.info("Running in simulation mode as fallback...")
            self._simulate_packets()

    def export_data(self) -> None:
        """Save results to CSV if pandas is available."""
        if pd is not None and self.packet_data:
            df = pd.DataFrame(self.packet_data)
            df.to_csv(self.csv_file, index=False)
            logger.info(f"Security report exported to {self.csv_file}")
        elif not self.packet_data:
            logger.info("No packets captured for export.")

    def run_analytics(self) -> None:
        """Generate summary and visualizations."""
        total = len(self.packet_data)
        if total == 0:
            logger.info("Insufficient data for analytics.")
            return

        tcp_count = sum(1 for p in self.packet_data if p["Protocol"] == 6)
        udp_count = sum(1 for p in self.packet_data if p["Protocol"] == 17)
        top_talkers = sorted(self.ip_counter.items(), key=lambda x: x[1], reverse=True)[:5]

        print("\n" + "="*30)
        print("SECURITY SUMMARY STATISTICS")
        print("="*30)
        print(f"Total Packets: {total}")
        print(f"TCP/UDP Ratio: {tcp_count}/{udp_count}")
        print("\nTOP 5 SOURCE IPs:")
        for ip, count in top_talkers:
            print(f"- {ip}: {count} packets")
        print("="*30 + "\n")

        if plt and total > 0:
            self._display_charts(tcp_count, udp_count, top_talkers)

    def _display_charts(self, tcp_count: int, udp_count: int, top_talkers: List) -> None:
        """Internal method for plot rendering."""
        try:
            plt.figure(figsize=(12, 6))
            
            # Protocol Distribution
            plt.subplot(1, 2, 1)
            plt.bar(['TCP', 'UDP'], [tcp_count, udp_count], color=['#2c3e50', '#27ae60'])
            plt.title('Protocol Intensity')
            plt.ylabel('Packets')

            # Top Talkers
            plt.subplot(1, 2, 2)
            ips = [x[0] for x in top_talkers]
            counts = [x[1] for x in top_talkers]
            plt.bar(ips, counts, color='#c0392b')
            plt.title('Top Network Talkers')
            plt.xticks(rotation=45)

            plt.tight_layout()
            plt.show()
        except Exception as e:
            logger.error(f"Visualization aborted: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="LordRadez-Network-Sentinel")
    parser.add_argument("-c", "--count", type=int, default=100, help="Packet capture count")
    parser.add_argument("-t", "--threshold", type=int, default=50, help="DoS detection threshold")
    
    parser.add_argument("-s", "--simulate", action="store_true", help="Run in simulation mode (demo)")
    
    args = parser.parse_args()

    sentinel = NetworkSentinel(capture_count=args.count, dos_threshold=args.threshold)
    sentinel.start(simulate=args.simulate)
    sentinel.export_data()
    sentinel.run_analytics()