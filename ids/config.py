INTERFACE = "eth0"  # Change this to your interface, e.g. Wi-Fi, Ethernet, en0, wlan0

SUSPICIOUS_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    3389: "RDP",
    4444: "Common reverse shell port",
}

PACKET_RATE_THRESHOLD = 50
TRACKING_WINDOW_SECONDS = 10