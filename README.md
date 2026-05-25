# Multipurpose Network Packet Sniffer and Logger

A lightweight Python-based packet sniffer built with Scapy. This tool captures live network traffic, identifies common protocols, applies user-defined packet filters, and logs suspicious packets using a basic heuristic engine.

## Architecture

- `sniffer.py` - main CLI script.
  - Uses Scapy's `sniff()` to capture live packets.
  - Parses layer-2, layer-3, and layer-4 headers to identify protocols like Ethernet, ARP, IPv4, IPv6, TCP, UDP, ICMP.
  - Supports optional capture filters for `tcp`, `udp`, `icmp`, or `host <IP>`.
  - Detects potentially suspicious activity and writes details to `suspicious_activity.log`.
  - Displays a clean console summary in real time and prints final statistics on exit.

## Requirements

- Python 3.8+
- `scapy`

Install dependencies:

```bash
pip install -r requirements.txt
```

## Running the Sniffer

Because packet sniffing requires privileged access, run the script using administrative privileges.

On Linux/macOS:

```bash
sudo python3 sniffer.py
```

On Windows (Command Prompt as Administrator):

```powershell
python sniffer.py
```

### Example usage

Capture all packets on the default interface:

```bash
sudo python3 sniffer.py
```

Capture only TCP traffic:

```bash
sudo python3 sniffer.py --filter tcp
```

Capture traffic to or from a specific host:

```bash
sudo python3 sniffer.py --filter "host 192.168.1.1"
```

## Suspicious Activity Logging

The script writes flagged packet events to `suspicious_activity.log` in the project folder. Each entry includes a timestamp, the reason for the flag, source/destination addresses, and protocol details.

### What is flagged?

- High-volume ICMP bursts that may indicate ping flood or reconnaissance.
- TCP SYN packets without follow-up ACKs consistent with scanning behavior.
- Plain-text credentials on unencrypted protocols like HTTP and FTP.

## Ethical Use Warning

This tool is intended for authorized network monitoring, debugging, and security testing only. Do not use it to intercept traffic, scan networks, or collect data without explicit permission from the network owner.

Unauthorized packet capture may violate local laws, corporate policies, and privacy expectations.

## Log File Review

Open `suspicious_activity.log` with any text editor or use:

```bash
cat suspicious_activity.log
```

Look for timestamped entries describing suspicious packet patterns.
