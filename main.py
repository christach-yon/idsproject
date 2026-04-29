import socket
import sys
from datetime import datetime, timezone

from scapy.all import sniff, IP, ICMP
import psycopg


# -----------------------------
# DATABASE CONFIG
# -----------------------------
DB_CONFIG = {
    "host": "localhost",
    "port": 5432,
    "dbname": "ping_logger",
    "user": "chrisdiavolo",
    "password": "Password1"
}


# -----------------------------
# SQL
# -----------------------------
INSERT_SQL = """
INSERT INTO icmp_ping_logs (
    sensor_host,
    src_ip,
    dst_ip,
    icmp_type,
    icmp_code,
    captured_at
)
VALUES (%s, %s, %s, %s, %s, %s);
"""


def get_sensor_host() -> str:
    """
    Returns the hostname of the machine running this sniffer.
    This is the 'machine got the ping' / machine observing the ping traffic.
    """
    return socket.gethostname()


def save_ping_to_db(
    conn: psycopg.Connection,
    sensor_host: str,
    src_ip: str,
    dst_ip: str,
    icmp_type: int,
    icmp_code: int,
    captured_at: datetime
) -> None:
    """
    Insert one ICMP event into PostgreSQL.
    """
    with conn.cursor() as cur:
        cur.execute(
            INSERT_SQL,
            (sensor_host, src_ip, dst_ip, icmp_type, icmp_code, captured_at)
        )
    conn.commit()


def process_packet(packet, conn: psycopg.Connection, sensor_host: str) -> None:
    """
    Callback for each sniffed packet.
    Only logs ICMP packets that include IP + ICMP layers.
    """
    if IP not in packet or ICMP not in packet:
        return

    ip_layer = packet[IP]
    icmp_layer = packet[ICMP]

    # ICMP type 8 = Echo Request, 0 = Echo Reply
    if icmp_layer.type not in (0, 8):
        return

    src_ip = ip_layer.src
    dst_ip = ip_layer.dst
    icmp_type = int(icmp_layer.type)
    icmp_code = int(icmp_layer.code)
    captured_at = datetime.now(timezone.utc)

    try:
        save_ping_to_db(
            conn=conn,
            sensor_host=sensor_host,
            src_ip=src_ip,
            dst_ip=dst_ip,
            icmp_type=icmp_type,
            icmp_code=icmp_code,
            captured_at=captured_at
        )
        print(
            f"[+] Logged ICMP packet | "
            f"sensor_host={sensor_host} | "
            f"src={src_ip} | dst={dst_ip} | "
            f"type={icmp_type} | code={icmp_code} | "
            f"time={captured_at.isoformat()}"
        )
    except Exception as e:
        print(f"[!] Failed to insert packet into DB: {e}")


def main() -> None:
    sensor_host = get_sensor_host()

    print("[*] Starting ICMP sniffer...")
    print(f"[*] Sensor host: {sensor_host}")

    try:
        conn = psycopg.connect(**DB_CONFIG)
        print("[*] Connected to PostgreSQL.")
    except Exception as e:
        print(f"[!] Could not connect to PostgreSQL: {e}")
        sys.exit(1)

    try:
        # store=False prevents packets from building up in memory
        sniff(
            filter="icmp",
            prn=lambda pkt: process_packet(pkt, conn, sensor_host),
            store=False
        )
    except KeyboardInterrupt:
        print("\n[*] Stopping sniffer.")
    except Exception as e:
        print(f"[!] Sniffer error: {e}")
    finally:
        conn.close()
        print("[*] Database connection closed.")


if __name__ == "__main__":
    main()