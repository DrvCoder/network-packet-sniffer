# Network Packet Analyzer (Packet Sniffer)

A lightweight Python utility designed to capture and inspect raw network frames at the data link and network layers, demonstrating practical packet parsing and socket programming principles.

## Features

- **Raw Socket Manipulation:** Binds directly to network interfaces to intercept raw incoming and outgoing packets.
- **Protocol Parsing:** Decodes Ethernet frames and parses IPv4 headers to extract essential packet metadata (Source/Destination IP addresses, Protocol types, and Time-To-Live).
- **Real-Time Logging:** Prints structured network traffic summaries directly to the terminal for analysis.

## Prerequisites

- Python 3.x
- **Administrator / Root Access:** Required to capture raw socket traffic on Linux/Kali or Windows environments.

## Getting Started

1. **Clone the repository:**
   ```bash
   git clone [https://github.com/DrvCoder/network-packet-sniffer.git](https://github.com/DrvCoder/network-packet-sniffer.git)
   cd network-packet-sniffer