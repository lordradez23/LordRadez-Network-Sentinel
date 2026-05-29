# LordRadez-Network-Sentinel
**Real-time Network Intelligence & Security Sentinel — monitoring digital perimeters for suspicious activity.**

[![License](https://img.shields.io/badge/License-MIT-blue)](LICENSE)
[![Built by](https://img.shields.io/badge/Built%20by-LordRadez-black)](https://github.com/lordradez23)

![Sentinel Banner](assets/banner.png)

## The Problem
Modern network monitoring is often fragmented across multiple siloed tools. When a port scan begins on a gateway or a burst of UDP traffic hits a sensitive service, traditional systems frequently fail to connect these signals in real-time. This lack of correlation leads to delayed responses, where by the time a breach or a Denial of Service (DoS) attack is visible to administrators, the damage is already cascading across the infrastructure.

## The Solution
**LordRadez-Network-Sentinel** is a real-time intelligence platform designed to bridge these gaps. It monitors network traffic across multiple protocols—TCP, UDP, and IP—simultaneously. By applying real-time heuristic models and cross-layer correlation, the Sentinel detects multi-dimensional threats early. It triggers immediate alerts and automated logging for suspicious activity, such as port reconnaissance and traffic floods, providing administrators with actionable intelligence in under 30 seconds.

---

## Core Features
| Feature | Description |
| :--- | :--- |
| **Real-Time Inspection** | High-speed packet ingestion and deep-layer analysis powered by a custom Scapy implementation. |
| **Threat Heuristics** | Automated detection of DoS patterns and suspicious port reconnaissance (FTP, Telnet, RDP). |
| **Protocol Correlation** | Simultaneously monitors TCP/UDP distribution to identify infrastructure-wide imbalances. |
| **Live Alert Feed** | Instant console alerts for threshold breaches, maintaining a clean and actionable monitoring stream. |
| **Dynamic Visualizations** | Post-capture graphical analytics highlighting top network talkers and protocol usage ratios. |
| **Automated Reporting** | Generates chronological `alerts.log` and structured `network_report.csv` for post-incident audits. |
| **Adaptive Interface** | Dynamic network interface discovery ensuring high compatibility across diverse hardware environments. |

---

## Architecture
```text
┌─────────────────────────────────────────────────────────────────┐
│                 LordRadez-Network-Sentinel                      │
├──────────────────────┬──────────────────────────────────────────┤
│   Ingestion (Scapy)  │          Analysis Engine (Python)        │
│                      │                                           │
│  Sniffer Module      │  Heuristic Processor                      │
│    Active Sniff      │    DoS Counter (IP Tracking)              │
│    Layer Filter      │    Port Scanner Detection                 │
│  Interface Resolver  │    Protocol Balancer                      │
│                      │                                           │
│                      │  Data Flow Manager                       │
│                      │    Real-time Alerting                    │
│                      │    Persistent Logging                    │
│                      │    CSV Aggregation                       │
└──────────────────────┴──────────────────────────────────────────┘

┌──────────────────────────────────────────────────┐
│              Visualization & Reporting           │
│  Matplotlib Engine → Protocol Distribution Graph │
│  Pandas Processor → Network Report (CSV)         │
└──────────────────────────────────────────────────┘
```

---

## Tech Stack

### Core Engine
- **Python 3.8+**
- **Scapy** (High-level packet manipulation)
- **Collections (DefaultDict)** (Efficient IP state tracking)

### Data & Analytics
- **Pandas** (Structured data aggregation)
- **Matplotlib** (Statistical visualization)
- **CSV/Log** (Persistent storage)

---

## Getting Started

### Prerequisites
- Python 3.8 or later
- Administrative/Root privileges (required for raw socket access)
- Packet capture driver (NPCAP for Windows or libpcap for Linux/macOS)

### Installation
```bash
# Clone the repository
git clone https://github.com/lordradez23/LordRadez-Network-Sentinel.git
cd LordRadez-Network-Sentinel

# Setup environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dependencies
pip install scapy matplotlib pandas
```

### Usage
Run the Sentinel with administrative privileges:
```bash
python network_analyzer.py
```

---

## Business Model
**LordRadez-Network-Sentinel** is positioned for growth through multiple value channels:

| Channel | Description | Target |
| :--- | :--- | :--- |
| **Enterprise License** | Dedicated support and custom detection modules for corporate intranets. | SME Security Teams, Managed IT. |
| **Intelligence API** | Monthly subscription for raw threat feed integration into external SIEMs. | MSSPs, Security Operations Centers. |
| **Audit Services** | One-time network health and reconnaissance vulnerability audits. | Financial Institutions, Tech Startups. |

---

## Team
- **LordRadez** — Founder & Lead Engineer
- Focused on building high-performance, autonomous security toolsets for the African digital frontier.
- Developer of the **Sentinel** ecosystem for proactive threat intelligence.

---

## License
Distributed under the **MIT License**. See `LICENSE` for more information.

---

<p align="center">
  <b>LordRadez-Network-Sentinel</b> is a project by <b>LordRadez</b>.
</p>
