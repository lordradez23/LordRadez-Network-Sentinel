# LordRadez Network Sentinel

![Network Security Banner](assets/banner.png)

> **A professional-grade Python suite for real-time packet inspection, threat detection, and traffic visualization.**

Developed by **[lordradez](https://github.com/lordradez)**, this tool empowers security researchers and network administrators to monitor, analyze, and secure their environments with high-performance heuristics and elegant data reporting.

---

## Key Features

- **Real-Time Inspection**: High-speed packet capture (TCP/UDP/IP) powered by Scapy.
- **Intelligent Threat Detection**:
    - **DoS Protection**: Automated alerts for suspicious traffic spikes (adjustable thresholds).
    - **Vulnerability Scanning**: Flags unauthorized ingress on high-risk ports (FTP, Telnet, RDP).
- **Dynamic Visualizations**: Instant analytics for protocol distribution and top network talkers via Matplotlib.
- **Automated Reporting**:
    - `alerts.log`: Chronological record of security events.
    - `network_report.csv`: Complete traffic breakdown for deep-dive analysis.
- **Optimized Performance**: Designed with efficiency in mind for low-latency monitoring.

---

## Quick Start

### 1. Prerequisites
Ensure you have Python 3.8+ installed. You also need a packet capture driver (NPCAP for Windows or libpcap for Linux/macOS).

### 2. Installation
```bash
# Clone the repository
git clone https://github.com/lordradez/network-security-analyzer.git
cd network-security-analyzer

# Setup environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dependencies
pip install scapy matplotlib pandas
```

### 3. Usage
Run the analyzer with administrative privileges:
```bash
python network_analyzer.py
```

---

## Configuration
The tool is highly configurable via the `CONFIG` section in `network_analyzer.py`:

```python
CAPTURE_COUNT = 100       # Number of packets to capture
DOS_THRESHOLD = 50       # Flag IP after X packets
SUSPICIOUS_PORTS = {21, 23, 3389} # Monitored ports
```

---

## Architecture

The **Network Sentinel** follows a decoupled architecture:
1. **Sniffer Module**: Utilizes the Scapy engine for raw packet ingestion.
2. **Analysis Engine**: A heuristic-based processing unit that evaluates safety flags in real-time.
3. **Data Processor**: Aggregates metrics using Pandas for persistent storage.
4. **UI/Graphing**: Renders cryptographic and statistical insights post-capture.

---

## Contributing
Contributions are what make the open-source community such an amazing place to learn, inspire, and create. Any contributions you make are **greatly appreciated**.

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## License
Distributed under the MIT License. See `LICENSE` for more information.

---

<p align="center">
  Developed with care by <b>lordradez</b>
</p>
