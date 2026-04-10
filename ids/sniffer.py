from scapy.all import sniff, IP, TCP, UDP, ICMP
from queue import Queue
from utils import timestamp


class PacketSniffer:
    def __init__(self, interface: str, packet_queue: Queue):
        self.interface = interface
        self.packet_queue = packet_queue

    def process_packet(self, packet):
        packet_data = {
            "timestamp": timestamp(),
            "src_ip": None,
            "dst_ip": None,
            "protocol": "OTHER",
            "src_port": None,
            "dst_port": None,
            "length": len(packet)
        }

        if IP in packet:
            packet_data["src_ip"] = packet[IP].src
            packet_data["dst_ip"] = packet[IP].dst

        if TCP in packet:
            packet_data["protocol"] = "TCP"
            packet_data["src_port"] = packet[TCP].sport
            packet_data["dst_port"] = packet[TCP].dport

        elif UDP in packet:
            packet_data["protocol"] = "UDP"
            packet_data["src_port"] = packet[UDP].sport
            packet_data["dst_port"] = packet[UDP].dport

        elif ICMP in packet:
            packet_data["protocol"] = "ICMP"

        try:
            self.packet_queue.put(packet_data, block=False)
        except Exception:
            # queue full, drop packet instead of blocking capture
            pass

    def start(self):
        sniff(iface=self.interface, prn=self.process_packet, store=False)
