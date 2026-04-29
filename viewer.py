import psycopg


DB_CONFIG = {
    "host": "127.0.0.1",
    "port": 5432,
    "dbname": "ping_logger",
    "user": "chrisdiavolo",
    "password": "Password1"
}


SELECT_SQL = """
SELECT
    id,
    sensor_host,
    src_ip,
    dst_ip,
    icmp_type,
    icmp_code,
    captured_at
FROM icmp_ping_logs
ORDER BY captured_at DESC
LIMIT 50;
"""


def format_table(rows, headers):
    """
    Build a clean text table without extra libraries.
    """
    if not rows:
        return "No rows found."

    str_rows = []
    for row in rows:
        str_rows.append([str(value) for value in row])

    widths = []
    for i, header in enumerate(headers):
        max_width = len(header)
        for row in str_rows:
            if len(row[i]) > max_width:
                max_width = len(row[i])
        widths.append(max_width)

    def make_separator():
        return "+-" + "-+-".join("-" * width for width in widths) + "-+"

    def make_row(values):
        return "| " + " | ".join(value.ljust(widths[i]) for i, value in enumerate(values)) + " |"

    lines = []
    lines.append(make_separator())
    lines.append(make_row(headers))
    lines.append(make_separator())

    for row in str_rows:
        lines.append(make_row(row))

    lines.append(make_separator())
    return "\n".join(lines)


def main():
    try:
        conn = psycopg.connect(**DB_CONFIG)
    except Exception as e:
        print(f"[!] Could not connect to database: {e}")
        return

    try:
        with conn.cursor() as cur:
            cur.execute(SELECT_SQL)
            rows = cur.fetchall()

        headers = [
            "id",
            "sensor_host",
            "src_ip",
            "dst_ip",
            "icmp_type",
            "icmp_code",
            "captured_at"
        ]

        print("\nICMP LOG VIEWER\n")
        print(format_table(rows, headers))

    except Exception as e:
        print(f"[!] Query failed: {e}")
    finally:
        conn.close()


if __name__ == "__main__":
    main()