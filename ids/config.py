INTERFACE = r"\Device\NPF_{4FD77573-F36B-41ED-B287-68DF01A60DB7}"  # Change if needed

SUSPICIOUS_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    3389: "RDP",
    4444: "Common reverse shell port",
}

PACKET_RATE_THRESHOLD = 10
TRACKING_WINDOW_SECONDS = 10

# Port scan detection
PORT_SCAN_UNIQUE_PORT_THRESHOLD = 5
PORT_SCAN_WINDOW_SECONDS = 15

# Alert cooldown / dedupe
ALERT_COOLDOWN_SECONDS = 5