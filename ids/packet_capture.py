from typing import Callable, Dict, Any
import pyshark


def extract_packet_info(packet) -> Dict[str, Any]:
    packet_info = {
        "src_ip": None,
        "dst_ip": None,
        "src_port": None,
        "dst_port": None,
        "protocol": None,
        "length": None,
        "tcp_flags": None,
    }

    try:
        if hasattr(packet, "ip"):
            packet_info["src_ip"] = getattr(packet.ip, "src", None)
            packet_info["dst_ip"] = getattr(packet.ip, "dst", None)

        if hasattr(packet, "tcp"):
            packet_info["protocol"] = "TCP"
            packet_info["src_port"] = getattr(packet.tcp, "srcport", None)
            packet_info["dst_port"] = getattr(packet.tcp, "dstport", None)
            packet_info["tcp_flags"] = getattr(packet.tcp, "flags", None)

        elif hasattr(packet, "udp"):
            packet_info["protocol"] = "UDP"
            packet_info["src_port"] = getattr(packet.udp, "srcport", None)
            packet_info["dst_port"] = getattr(packet.udp, "dstport", None)

        else:
            packet_info["protocol"] = getattr(packet, "highest_layer", "UNKNOWN")

        packet_info["length"] = int(getattr(packet, "length", 0))

    except Exception as exc:
        print(f"[!] Error extracting packet info: {exc}")

    return packet_info


def start_capture(interface: str, packet_callback: Callable[[Dict[str, Any]], None]) -> None:
    capture = pyshark.LiveCapture(interface=interface)

    try:
        for packet in capture.sniff_continuously():
            packet_info = extract_packet_info(packet)
            packet_callback(packet_info)

    except KeyboardInterrupt:
        print("\n[*] Capture stopped by user.")

    except Exception as exc:
        print(f"[!] Capture error: {exc}")