"""
constants.py — Centralised configuration for the Cyber Threat Dashboard.

All shared regex patterns, MITRE mappings, paths, GeoIP data, and tunables
live here so that app.py and agent_platform.py import rather than duplicate.
"""

import os

# ---------------------------------------------------------------------------
# Paths (relative to this file — project root)
# ---------------------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE_PATH = os.path.join(BASE_DIR, 'mock_auth.log')
REPORT_FILE_PATH = os.path.join(BASE_DIR, 'mitigation_report.json')
INDEX_HTML_PATH = os.path.join(BASE_DIR, 'index.html')

# ---------------------------------------------------------------------------
# Regex patterns for syslog parsing  (used by app.py → parse_log_line)
# ---------------------------------------------------------------------------
SSH_FAIL_PATTERN = r'sshd\[\d+\]: Failed password for (?:invalid user )?(\S+) from (\S+) port (\d+)'
SSH_ACCEPT_PATTERN = r'sshd\[\d+\]: Accepted password for (\S+) from (\S+) port (\d+)'
WEB_CONN_PATTERN = r'web-server\[\d+\]: CONNECT: Client "(\S+)" Request: "(.+)"'
WEB_FAIL_PATTERN = r'web-server\[\d+\]: FAIL LOGIN: Client "(\S+)", user "(\S+)"'
WEB_EXPLOIT_PATTERN = r'web-server\[\d+\]: WARNING: ([\w\s]+? (?:attempt|signature) detected) from (\S+) - Uri: (\S+)'
SUDO_PATTERN = r'sudo\[\d+\]: (\S+) : TTY=\S+ ; PWD=\S+ ; USER=(\S+) ; COMMAND=(.+)'
FIREWALL_PATTERN = r'custom-firewall\[\d+\]: (BLOCKED IP|UNBLOCKED IP): (\S+) added to iptables active rules\.'

# ---------------------------------------------------------------------------
# MITRE ATT&CK mapping  (fallback for agent_platform.py)
# ---------------------------------------------------------------------------
MITRE_ATTACK_DB = {
    "sshd_fail": {"vector": "SSH Brute Force", "mitre_id": "T1110 - Brute Force"},
    "sshd_accept_external": {"vector": "Suspicious External Login", "mitre_id": "T1078 - Valid Accounts"},
    "web_fail": {"vector": "Web Authentication Bruteforce", "mitre_id": "T1110.001 - Brute Force: Password Guessing"},
    "web_sql": {"vector": "SQL Injection (Data Leak)", "mitre_id": "T1190 - Exploit Public-Facing Application"},
    "web_traversal": {"vector": "Directory Traversal", "mitre_id": "T1190 - Exploit Public-Facing Application"},
    "sudo_abuse": {"vector": "Sudo Privilege Escalation", "mitre_id": "T1548.003 - Abuse Elevation Control Mechanism"},
}

# ---------------------------------------------------------------------------
# Mock GeoIP database
# ---------------------------------------------------------------------------
MOCK_GEOIP = {
    "127.0.0.1": {"country": "Local Loopback", "cc": "LAN", "lat": 0, "lon": 0},
    "192.168.1.100": {"country": "Local Network", "cc": "LAN", "lat": 0, "lon": 0},
    "192.168.1.101": {"country": "Local Network", "cc": "LAN", "lat": 0, "lon": 0},
    "195.133.40.12": {"country": "Russia", "cc": "RU", "lat": 55.7558, "lon": 37.6173},
    "103.24.140.66": {"country": "India", "cc": "IN", "lat": 20.5937, "lon": 78.9629},
    "45.143.203.11": {"country": "China", "cc": "CN", "lat": 39.9042, "lon": 116.4074},
    "185.220.101.5": {"country": "Germany", "cc": "DE", "lat": 52.5200, "lon": 13.4050},
    "185.220.101.8": {"country": "Germany", "cc": "DE", "lat": 52.5200, "lon": 13.4050},
    "91.241.19.82": {"country": "Ukraine", "cc": "UA", "lat": 50.4501, "lon": 30.5234},
    "82.102.23.4": {"country": "Netherlands", "cc": "NL", "lat": 52.3676, "lon": 4.9041},
    "80.82.77.33": {"country": "Netherlands", "cc": "NL", "lat": 52.3676, "lon": 4.9041},
    "212.102.33.15": {"country": "United States", "cc": "US", "lat": 37.0902, "lon": -95.7129},
    "198.51.100.42": {"country": "United States", "cc": "US", "lat": 40.7128, "lon": -74.0060},
    "81.2.222.12": {"country": "United Kingdom", "cc": "GB", "lat": 51.5074, "lon": -0.1278},
    "114.119.160.10": {"country": "Singapore", "cc": "SG", "lat": 1.3521, "lon": 103.8198},
}

DEFAULT_GEOIP = {"country": "Unknown", "cc": "Unknown", "lat": 0, "lon": 0}

GEOIP_FALLBACK_COUNTRIES = [
    {"country": "United States", "cc": "US", "lat": 37.0902, "lon": -95.7129},
    {"country": "Russia", "cc": "RU", "lat": 55.7558, "lon": 37.6173},
    {"country": "China", "cc": "CN", "lat": 39.9042, "lon": 116.4074},
    {"country": "Germany", "cc": "DE", "lat": 52.5200, "lon": 13.4050},
    {"country": "India", "cc": "IN", "lat": 20.5937, "lon": 78.9629},
    {"country": "Brazil", "cc": "BR", "lat": -14.2350, "lon": -51.9253},
    {"country": "South Korea", "cc": "KR", "lat": 35.9078, "lon": 127.7669},
    {"country": "Vietnam", "cc": "VN", "lat": 14.0583, "lon": 108.2772},
]


def get_geoip_details(ip: str) -> dict:
    """Return mock GeoIP data for *ip*, with deterministic fallback."""
    if ip in MOCK_GEOIP:
        return MOCK_GEOIP[ip]
    if ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172."):
        return {"country": "Local Network", "cc": "LAN", "lat": 0, "lon": 0}
    try:
        last_octet = int(ip.split(".")[-1])
    except (ValueError, IndexError):
        last_octet = 0
    return GEOIP_FALLBACK_COUNTRIES[last_octet % len(GEOIP_FALLBACK_COUNTRIES)]


# ---------------------------------------------------------------------------
# Rate-limiting tunables
# ---------------------------------------------------------------------------
RATE_LIMIT_WINDOW_SECONDS = 60   # sliding window length
RATE_LIMIT_MAX_REQUESTS = 120    # max requests per window per client IP

# ---------------------------------------------------------------------------
# Server tunables
# ---------------------------------------------------------------------------
MAX_REQUEST_BODY_BYTES = 4096    # cap POST body size to prevent memory abuse
