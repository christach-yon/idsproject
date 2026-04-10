import threading
from queue import Queue
from config import INTERFACE, QUEUE_MAXSIZE
from sniffer import PacketSniffer
from filter_logger import TrafficFilterLogger


def main():
    packet_queue = Queue(maxsize=QUEUE_MAXSIZE)

    sniffer = PacketSniffer(INTERFACE, packet_queue)
    filter_logger = TrafficFilterLogger(packet_queue)

    sniffer_thread = threading.Thread(target=sniffer.start, daemon=True)
    logger_thread = threading.Thread(target=filter_logger.run, daemon=True)

    sniffer_thread.start()
    logger_thread.start()

    print(f"[*] Traffic monitor started on interface: {INTERFACE}")
    print("[*] Press Ctrl+C to stop.")

    try:
        while True:
            pass
    except KeyboardInterrupt:
        print("\n[*] Shutting down...")
        filter_logger.running = False


if __name__ == "__main__":
    main()
