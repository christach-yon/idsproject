import argparse

from ids.packet_capture import start_capture
from ids.detector import SimpleIDS
from ids.logger import setup_logger
from ids.config import INTERFACE


def main() -> None:
    parser = argparse.ArgumentParser(description="Simple IDS prototype using PyShark")
    parser.add_argument(
        "-i",
        "--interface",
        default=INTERFACE,
        help="Network interface to capture from",
    )
    args = parser.parse_args()

    logger = setup_logger()
    ids_engine = SimpleIDS(logger=logger)

    print(f"[*] Starting IDS on interface: {args.interface}")
    print("[*] Press Ctrl+C to stop.\n")

    start_capture(interface=args.interface, packet_callback=ids_engine.process_packet)


if __name__ == "__main__":
    main()