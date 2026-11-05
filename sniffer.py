#!/usr/bin/env python3
import os
import socket
import struct
import sys

def get_local_ip():
    """Helper to get local machine IP for Windows binding."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

def parse_ipv4_header(data):
    """Parses IPv4 header to extract source IP, destination IP, and protocol."""
    version_header_length = data[0]
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack("! 8x B B 2x 4s 4s", data[:20])
    src_ip = socket.inet_ntoa(src)
    target_ip = socket.inet_ntoa(target)
    return ttl, proto, src_ip, target_ip, data[header_length:]

def main():
    print("=" * 60)
    print("Starting Raw Network Packet Sniffer...")
    print("Press Ctrl+C to stop.")
    print("=" * 60)

    try:
        # Check operating system and initialize appropriate raw socket
        if os.name == 'nt':  # Windows Environment
            host = get_local_ip()
            print(f"[*] Binding to Windows local IP: {host}")
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            s.bind((host, 0))
            # Include IP headers in the captured data
            s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        else:  # Linux / Kali Environment
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    except PermissionError:
        print("\n[-] Error: Administrator / Root privileges required.")
        if os.name == 'nt':
            print("[-] Please run your PowerShell or Command Prompt as Administrator.")
        else:
            print("[-] Try running with 'sudo python3 sniffer.py'")
        sys.exit(1)
    except Exception as e:
        print(f"\n[-] Socket creation error: {e}")
        sys.exit(1)

    try:
        while True:
            raw_data, addr = s.recvfrom(65535)
            
            # On Windows, raw sockets capture IP packets directly
            if os.name == 'nt':
                ttl, proto, src_ip, target_ip, payload = parse_ipv4_header(raw_data)
                print(f"\n[+] IPv4 Packet Captured:")
                print(f"    Source IP      : {src_ip}")
                print(f"    Destination IP : {target_ip}")
                print(f"    Protocol       : {proto}")
                print(f"    TTL            : {ttl}")
            else:
                # Linux parsing logic handles Ethernet frame offset (14 bytes)
                if len(raw_data) >= 14:
                    ip_data = raw_data[14:]
                    ttl, proto, src_ip, target_ip, payload = parse_ipv4_header(ip_data)
                    print(f"\n[+] IPv4 Packet Captured:")
                    print(f"    Source IP      : {src_ip}")
                    print(f"    Destination IP : {target_ip}")
                    print(f"    Protocol       : {proto}")

    except KeyboardInterrupt:
        print("\n[!] Packet capture stopped by user. Exiting.")
        sys.exit()

if __name__ == "__main__":
    main()