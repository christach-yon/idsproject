from typing import Any, Dict

from ids.config import (
    SUSPICIOUS_PORTS,
    PACKET_RATE_THRESHOLD,
    TRACKING_WINDOW_SECONDS,
    PORT_SCAN_UNIQUE_PORT_THRESHOLD,
    PORT_SCAN_WINDOW_SECONDS,
    ALERT_COOLDOWN_SECONDS,
)
from ids.utils import RateTracker, PortScanTracker, AlertLimiter


class SimpleIDS:
    def __init__(self, logger):
        self.logger = logger
        self.rate_tracker = RateTracker(TRACKING_WINDOW_SECONDS)
        self.port_scan_tracker = PortScanTracker(PORT_SCAN_WINDOW_SECONDS)
        self.alert_limiter = AlertLimiter(ALERT_COOLDOWN_SECONDS)

    def process_packet(self, packet_info: Dict[str, Any]) -> None:
        src_ip = packet_info.get("src_ip", "Unknown")
        dst_ip = packet_info.get("dst_ip", "Unknown")
        protocol = packet_info.get("protocol", "Unknown")
        dst_port = packet_info.get("dst_port")
        tcp_flags = packet_info.get("tcp_flags")

        # Improvement 2:
        # Ignore local-to-local traffic to reduce home network noise.
        if self._is_private_ip(src_ip) and self._is_private_ip(dst_ip):
            return

        self._check_suspicious_port(src_ip, dst_ip, dst_port, protocol)
        self._check_syn_scan(src_ip, dst_ip, tcp_flags, protocol)
        self._check_packet_rate(src_ip)
        self._check_port_scan(src_ip, dst_ip, dst_port, protocol)

    def _check_suspicious_port(self, src_ip: str, dst_ip: str, dst_port: Any, protocol: str) -> None:
        if dst_port is None:
            return

        try:
            port = int(dst_port)
        except (ValueError, TypeError):
            return

        if port in SUSPICIOUS_PORTS:
            if self.alert_limiter.should_alert(src_ip, f"suspicious_port_{port}"):
                # Improvement 4:
                # Warning-level alert
                self.logger.warning(
                    f"[WARN] Suspicious port: {src_ip} -> {dst_ip}:{port} "
                    f"({SUSPICIOUS_PORTS[port]}) [{protocol}]"
                )

    def _check_syn_scan(self, src_ip: str, dst_ip: str, tcp_flags: Any, protocol: str) -> None:
        if protocol != "TCP" or tcp_flags is None:
            return

        flag_value = str(tcp_flags).lower()

        if flag_value in {"0x0002", "2", "syn"}:
            if self.alert_limiter.should_alert(src_ip, "syn_scan"):
                # Improvement 4:
                # Warning-level alert
                self.logger.warning(
                    f"[WARN] Possible SYN scan: {src_ip} -> {dst_ip} [flags={tcp_flags}]"
                )

    def _check_packet_rate(self, src_ip: str) -> None:
        count = self.rate_tracker.add_event(src_ip)

        if count > PACKET_RATE_THRESHOLD:
            if self.alert_limiter.should_alert(src_ip, "high_packet_rate"):
                # Improvement 4:
                # Warning-level alert
                self.logger.warning(
                    f"[WARN] High packet rate from {src_ip}: "
                    f"{count} packets in tracking window"
                )

    def _check_port_scan(self, src_ip: str, dst_ip: str, dst_port: Any, protocol: str) -> None:
        if dst_port is None:
            return

        try:
            port = int(dst_port)
        except (ValueError, TypeError):
            return

        unique_port_count = self.port_scan_tracker.add_port_hit(src_ip, port)

        if unique_port_count >= PORT_SCAN_UNIQUE_PORT_THRESHOLD:
            if self.alert_limiter.should_alert(src_ip, "port_scan"):
                ports = sorted(self.port_scan_tracker.get_unique_ports(src_ip))
                ports_preview = ", ".join(str(p) for p in ports[:15])

                if len(ports) > 15:
                    ports_preview += ", ..."

                # Improvement 4:
                # Error-level alert for more serious behavior
                self.logger.error(
                    f"[CRITICAL] Possible port scan from {src_ip} -> {dst_ip} "
                    f"| Unique ports hit in {PORT_SCAN_WINDOW_SECONDS}s: {unique_port_count} "
                    f"| Ports: {ports_preview} [{protocol}]"
                )

    def _is_private_ip(self, ip: str) -> bool:
        if not isinstance(ip, str):
            return False

        return (
            ip.startswith("10.")
            or ip.startswith("192.168.")
            or ip.startswith("172.16.")
            or ip.startswith("172.17.")
            or ip.startswith("172.18.")
            or ip.startswith("172.19.")
            or ip.startswith("172.20.")
            or ip.startswith("172.21.")
            or ip.startswith("172.22.")
            or ip.startswith("172.23.")
            or ip.startswith("172.24.")
            or ip.startswith("172.25.")
            or ip.startswith("172.26.")
            or ip.startswith("172.27.")
            or ip.startswith("172.28.")
            or ip.startswith("172.29.")
            or ip.startswith("172.30.")
            or ip.startswith("172.31.")
        )