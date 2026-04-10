# idsproject
Developing a prototype and concept for an Intrusion Detection System.

## Threat detection included
The IDS now raises alerts for:
- Suspicious ports (FTP/SSH/Telnet/RDP/reverse-shell patterns)
- SYN scan behavior
- High packet rate spikes
- Multi-port scan behavior from a single source
- ICMP flood patterns
- Repeated authentication-targeted connection attempts (basic brute-force heuristic)
- Large UDP payload anomalies
