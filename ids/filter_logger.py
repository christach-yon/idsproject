import os
from queue import Queue, Empty
from config import LOG_FILE, WATCH_PORTS, WATCH_PROTOCOLS


class TrafficFilterLogger:
    def __init__(self, packet_queue: Queue):
        self.packet_queue = packet_queue
        self.running = True

        os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

    def is_meaningful(self, packet: dict) -> bool:
        protocol = packet.get("protocol")
        src_port = packet.get("src_port")
        dst_port = packet.get("dst_port")

        if protocol not in WATCH_PROTOCOLS:
            return False

        if protocol in {"TCP", "UDP"}:
            if src_port in WATCH_PORTS or dst_port in WATCH_PORTS:
                return True
            return False

        if protocol == "ICMP":
            return True

        return False

    def format_log(self, packet: dict) -> str:
        return (
            f"[{packet['timestamp']}] "
            f"{packet['protocol']} "
            f"{packet['src_ip']}:{packet['src_port']} -> "
            f"{packet['dst_ip']}:{packet['dst_port']} "
            f"len={packet['length']}"
        )

    def write_log(self, message: str):
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(message + "\n")

    def run(self):
        while self.running:
            try:
                packet = self.packet_queue.get(timeout=1)
                if self.is_meaningful(packet):
                    log_entry = self.format_log(packet)
                    print(log_entry)
                    self.write_log(log_entry)
            except Empty:
                continue
            except KeyboardInterrupt:
                self.running = False
