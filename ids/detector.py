from typing import Any, Dict

from ids.config import SUSPICIOUS_PORTS, PACKET_RATE_THRESHOLD, TRACKING_WINDOW_SECONDS
from ids.utils import RateTracker


class SimpleIDS:
    def __init__(self, logger):
        self.logger = logger
        self.rate_tracker = RateTracker(TRACKING_WINDOW_SECONDS)

    def process_packet(self, packet_info: Dict[str, Any]) -> None:
        src_ip = packet_info.get("src_ip", "Unknown")
        dst_ip = packet_info.get("dst_ip", "Unknown")
        protocol = packet_info.get("protocol", "Unknown")
        src_port = packet_info.get("src_port")
        dst_port = packet_info.get("dst_port")
        tcp_flags = packet_info.get("tcp_flags")

        # Only run detection checks (NO SPAM LOGGING)
        self._check_suspicious_port(src_ip, dst_ip, dst_port, protocol)
        self._check_syn_scan(src_ip, dst_ip, tcp_flags, protocol)
        self._check_packet_rate(src_ip)

    def _check_suspicious_port(self, src_ip: str, dst_ip: str, dst_port: Any, protocol: str) -> None:
        if dst_port is None:
            return

        try:
            port = int(dst_port)
            if port in SUSPICIOUS_PORTS:
                self.logger.warning(
                    f"[ALERT] Suspicious port: {src_ip} → {dst_ip}:{port} "
                    f"({SUSPICIOUS_PORTS[port]}) [{protocol}]"
                )
        except ValueError:
            pass

    def _check_syn_scan(self, src_ip: str, dst_ip: str, tcp_flags: Any, protocol: str) -> None:
        if protocol != "TCP" or tcp_flags is None:
            return

        flag_value = str(tcp_flags).lower()

        if flag_value in {"0x0002", "2", "syn"}:
            self.logger.warning(
                f"[ALERT] Possible SYN scan: {src_ip} → {dst_ip} [flags={tcp_flags}]"
            )

    def _check_packet_rate(self, src_ip: str) -> None:
        count = self.rate_tracker.add_event(src_ip)

        if count > PACKET_RATE_THRESHOLD:
            self.logger.warning(
                f"[ALERT] High packet rate from {src_ip}: {count} packets"
            )