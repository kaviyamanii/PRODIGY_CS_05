# Prodigy_CS_05

# Network Packet Analyzer
Develop a packet sniffer tool that captures and analyzes network packets. Display relevant information such as source and destination IP addresses, protocols, and payload data. Ensure the ethical use of the tool for educational purposes.

## Features

- Packet Capture: Efficiently captures network packets on the specified interface.
- Protocol Analysis: Supports analysis of common protocols including TCP and UDP.
- IP Address Extraction: Displays source and destination IP addresses for each captured packet.
- Port Information: Extracts and shows source and destination ports for TCP and UDP packets.
- Payload Display: Provides raw payload data of the captured packets.
- Real-time Processing: Processes and displays packet information in real-time.
- Extensibility: Easily extendable to support additional protocols and advanced filtering.
- Platform Compatibility: Compatible with major operating systems including Linux, macOS, and Windows (with necessary permissions).

## Prerequisites
- python
- scapy library (pip install scapy)

## Usage

1. Open a terminal or command prompt.

2. Navigate to the directory where the script is located.

3. Run the script using Python:

   ```sh
   python networkanalyzer.py
