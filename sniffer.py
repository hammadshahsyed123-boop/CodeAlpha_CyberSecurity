
from scapy.all import sniff, IP, TCP, UDP, wrpcap, get_if_list
import datetime
import sys

def list_ifaces():
    print("Available network interfaces:")
    for i in get_if_list():
        print(" -", i)

def printable_payload(payload_bytes):
    try:
        return payload_bytes.decode('utf-8', errors='replace')
    except Exception:
        return str(payload_bytes)

def process_packet(packet):
    if IP in packet:
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        src = packet[IP].src
        dst = packet[IP].dst
        proto = packet[IP].proto
        proto_name = {6: "TCP", 17: "UDP"}.get(proto, str(proto))

        print(f"[{ts}] {src} -> {dst} | {proto_name}")
        if packet.haslayer(TCP) or packet.haslayer(UDP):
            payload = bytes(packet[TCP].payload) if packet.haslayer(TCP) else bytes(packet[UDP].payload)
            if payload:
        
                print("    Payload (first 120 bytes):")
                print("    ", printable_payload(payload[:120]))

if __name__ == "__main__":
   
    if len(sys.argv) > 1 and sys.argv[1] in ("-l", "--list"):
        list_ifaces()
        sys.exit(0)

    iface = sys.argv[1] if len(sys.argv) >= 2 else None
    timeout = int(sys.argv[2]) if len(sys.argv) >= 3 else None
    pcap_file = sys.argv[3] if len(sys.argv) >= 4 else None

    print("Starting capture. Interface:", iface or "default", " timeout:", timeout or "none")
    captured = sniff(iface=iface, filter="ip", prn=process_packet, timeout=timeout, store=True)
    print(f"Captured {len(captured)} packets.")

    if pcap_file:
        wrpcap(pcap_file, captured)
        print("Saved capture to", pcap_file)