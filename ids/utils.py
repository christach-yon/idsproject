from collections import defaultdict, deque
from time import time
from typing import Dict, Deque, Tuple, Set


class RateTracker:
    def __init__(self, window_seconds: int):
        self.window_seconds = window_seconds
        self.packet_times: Dict[str, Deque[float]] = defaultdict(deque)

    def add_event(self, source_ip: str) -> int:
        now = time()
        timestamps = self.packet_times[source_ip]
        timestamps.append(now)

        while timestamps and now - timestamps[0] > self.window_seconds:
            timestamps.popleft()

        return len(timestamps)


class PortScanTracker:
    def __init__(self, window_seconds: int):
        self.window_seconds = window_seconds
        self.events: Dict[str, Deque[Tuple[float, int]]] = defaultdict(deque)

    def add_port_hit(self, source_ip: str, dst_port: int) -> int:
        now = time()
        source_events = self.events[source_ip]
        source_events.append((now, dst_port))

        while source_events and now - source_events[0][0] > self.window_seconds:
            source_events.popleft()

        unique_ports: Set[int] = {port for _, port in source_events}
        return len(unique_ports)

    def get_unique_ports(self, source_ip: str) -> Set[int]:
        now = time()
        source_events = self.events[source_ip]

        while source_events and now - source_events[0][0] > self.window_seconds:
            source_events.popleft()

        return {port for _, port in source_events}


class AlertLimiter:
    def __init__(self, cooldown_seconds: int):
        self.cooldown_seconds = cooldown_seconds
        self.last_alert_time: Dict[Tuple[str, str], float] = {}

    def should_alert(self, source_ip: str, alert_type: str) -> bool:
        now = time()
        key = (source_ip, alert_type)
        last_time = self.last_alert_time.get(key)

        if last_time is None or (now - last_time) >= self.cooldown_seconds:
            self.last_alert_time[key] = now
            return True

        return False