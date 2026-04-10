from collections import defaultdict, deque
from time import time


class RateTracker:
    def __init__(self, window_seconds: int):
        self.window_seconds = window_seconds
        self.packet_times = defaultdict(deque)

    def add_event(self, source_ip: str) -> int:
        now = time()
        timestamps = self.packet_times[source_ip]
        timestamps.append(now)

        while timestamps and now - timestamps[0] > self.window_seconds:
            timestamps.popleft()

        return len(timestamps)