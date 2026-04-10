INTERFACE = "eth0"
LOG_FILE = "logs/events.log"

# Traffic filters
WATCH_PORTS = {22, 23, 80, 443, 3389}
WATCH_PROTOCOLS = {"TCP", "UDP", "ICMP"}

# Behavior
QUEUE_MAXSIZE = 1000
