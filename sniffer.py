#!/usr/bin/env python3

import argparse
import datetime
import logging
import os
import signal
import sys
import threading
import time
from collections import Counter, defaultdict, deque

from scapy.all import ARP, Ether, ICMP, IP, IPv6, TCP, UDP, conf, sniff, Raw

LOG_FILE = "suspicious_activity.log"
ICMP_BURST_THRESHOLD = 20
ICMP_WINDOW_SECONDS = 10
SYN_SCAN_PORT_THRESHOLD = 10
SYN_SCAN_WINDOW = 15

packet_counts = Counter()
suspicious_count = 0
lock = threading.Lock()
start_time = time.time()

icmp_events = deque()
syn_events = defaultdict(lambda: deque())

logging.basicConfig(
    filename=LOG_FILE,
    filemode="a",
    level=logging.INFO,
    format="%(asctime)s %(message)s",
)


def get_protocol_summary(packet):
    layers = []

    if packet.haslayer(Ether):
        layers.append("Ethernet")
    if packet.haslayer(ARP):
        layers.append("ARP")
    if packet.haslayer(IP):
        layers.append("IPv4")
    if packet.haslayer(IPv6):
        layers.append("IPv6")
    if packet.haslayer(TCP):
        layers.append("TCP")
    if packet.haslayer(UDP):
        layers.append("UDP")
    if packet.haslayer(ICMP):
        layers.append("ICMP")
    if packet.haslayer(Raw) and "HTTP" in repr(packet[Raw]):
        layers.append("HTTP")

    return "+".join(layers) if layers else packet.name


def get_packet_addresses(packet):
    src = dst = "unknown"
    if packet.haslayer(IP):
        src = packet[IP].src
        dst = packet[IP].dst
    elif packet.haslayer(IPv6):
        src = packet[IPv6].src
        dst = packet[IPv6].dst
    elif packet.haslayer(ARP):
        src = packet[ARP].psrc
        dst = packet[ARP].pdst
    elif packet.haslayer(Ether):
        src = packet[Ether].src
        dst = packet[Ether].dst

    return src, dst


def log_suspicious(packet, reason):
    global suspicious_count
    src, dst = get_packet_addresses(packet)
    proto = get_protocol_summary(packet)
    length = len(packet)
    message = f"[{reason}] {src} -> {dst} | {proto} | len={length}"

    with lock:
        suspicious_count += 1
        logging.info(message)

    print(f"[!] Suspicious: {message}")


def is_plain_text_credential(packet):
    if not packet.haslayer(Raw) or not packet.haslayer(TCP):
        return False

    payload = packet[Raw].load
    try:
        text = payload.decode("utf-8", errors="ignore")
    except Exception:
        return False

    if packet[TCP].dport in {80, 21} or packet[TCP].sport in {80, 21}:
        keywords = ["username", "user=", "pass=", "password", "login", "Authorization"]
        if any(word in text.lower() for word in keywords):
            return True

    return False


def detect_suspicious(packet):
    now = time.time()

    if packet.haslayer(ICMP):
        icmp_events.append(now)
        while icmp_events and icmp_events[0] < now - ICMP_WINDOW_SECONDS:
            icmp_events.popleft()

        if len(icmp_events) >= ICMP_BURST_THRESHOLD:
            log_suspicious(packet, "ICMP burst detected")
            return

    if packet.haslayer(TCP):
        tcp = packet[TCP]
        flow_key = (packet[IP].src if packet.haslayer(IP) else packet[IPv6].src,
                    packet[IP].dst if packet.haslayer(IP) else packet[IPv6].dst)

        if tcp.flags == "S":
            syn_events[flow_key].append((now, tcp.dport))
            scan_ports = {port for timestamp, port in syn_events[flow_key] if timestamp >= now - SYN_SCAN_WINDOW}
            syn_events[flow_key] = deque([(ts, port) for ts, port in syn_events[flow_key] if ts >= now - SYN_SCAN_WINDOW])

            if len(scan_ports) >= SYN_SCAN_PORT_THRESHOLD:
                log_suspicious(packet, "Possible SYN scan detected")
                return

        if is_plain_text_credential(packet):
            log_suspicious(packet, "Plain-text credential transfer detected")
            return

    if packet.haslayer(ARP) and packet[ARP].op in (1, 2):
        if packet[ARP].psrc == "0.0.0.0" or packet[ARP].pdst == "255.255.255.255":
            log_suspicious(packet, "Unusual ARP traffic detected")
            return


def display_packet(packet):
    proto = get_protocol_summary(packet)
    src, dst = get_packet_addresses(packet)
    length = len(packet)
    print(f"{src} -> {dst} | {proto} | len={length}")


def handle_packet(packet):
    packet_counts["total"] += 1
    if packet.haslayer(TCP):
        packet_counts["tcp"] += 1
    if packet.haslayer(UDP):
        packet_counts["udp"] += 1
    if packet.haslayer(ICMP):
        packet_counts["icmp"] += 1
    if packet.haslayer(ARP):
        packet_counts["arp"] += 1
    if packet.haslayer(IP):
        packet_counts["ipv4"] += 1
    if packet.haslayer(IPv6):
        packet_counts["ipv6"] += 1

    display_packet(packet)
    detect_suspicious(packet)


def signal_handler(signum, frame):
    raise KeyboardInterrupt


def print_summary():
    elapsed = time.time() - start_time
    print("\nCapture stopped.")
    print(f"Duration: {elapsed:.1f} seconds")
    print(f"Total packets: {packet_counts['total']}")
    print(f"TCP: {packet_counts['tcp']}, UDP: {packet_counts['udp']}, ICMP: {packet_counts['icmp']}, ARP: {packet_counts['arp']}")
    print(f"IPv4: {packet_counts['ipv4']}, IPv6: {packet_counts['ipv6']}")
    print(f"Suspicious packets flagged: {suspicious_count}")
    print(f"Log file: {os.path.abspath(LOG_FILE)}")


def parse_args():
    parser = argparse.ArgumentParser(description="Lightweight network packet sniffer and suspicious activity logger.")
    parser.add_argument(
        "--filter",
        dest="capture_filter",
        help="Optional BPF filter string, such as 'tcp', 'udp', 'icmp', or 'host 192.168.1.1'",
        default=None,
    )
    parser.add_argument(
        "--interface",
        dest="interface",
        help="Optional network interface name. If omitted, Scapy will choose the default interface.",
        default=None,
    )
    return parser.parse_args()


def main():
    args = parse_args()
    interface = args.interface
    capture_filter = args.capture_filter

    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "a", encoding="utf-8") as _:
            pass

    print("Starting packet capture...")
    if interface:
        print(f"Interface: {interface}")
    if capture_filter:
        print(f"Filter: {capture_filter}")
    print("Press Ctrl+C to stop and show capture statistics.")

    signal.signal(signal.SIGINT, signal_handler)

    try:
        sniff(
            iface=interface,
            filter=capture_filter,
            prn=handle_packet,
            store=False,
        )
    except KeyboardInterrupt:
        print_summary()
    except PermissionError:
        print("Permission denied: run this script with elevated privileges.")
        sys.exit(1)
    except Exception as exc:
        print(f"An error occurred during packet capture: {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()
