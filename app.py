"""app.py — SOC Threat Dashboard backend."""
from __future__ import annotations

import os
import re
import json
import time
import random
import signal
import threading
import ipaddress
import dotenv
from http.server import BaseHTTPRequestHandler, HTTPServer

from constants import (
    BASE_DIR, LOG_FILE_PATH, INDEX_HTML_PATH,
    SSH_FAIL_PATTERN, SSH_ACCEPT_PATTERN, WEB_CONN_PATTERN,
    WEB_FAIL_PATTERN, WEB_EXPLOIT_PATTERN, SUDO_PATTERN, FIREWALL_PATTERN,
    RATE_LIMIT_WINDOW_SECONDS, RATE_LIMIT_MAX_REQUESTS,
    MAX_REQUEST_BODY_BYTES, get_geoip_details,
)

# Load environment variables
dotenv.load_dotenv()

# ---------------------------------------------------------------------------
# Thread-safe state
# ---------------------------------------------------------------------------
log_lock = threading.Lock()
blocked_ips = set()

# Simple in-memory rate-limit store  {client_ip: {"ts": float, "n": int}}
_rate_limit_store = {}

# ---------------------------------------------------------------------------
# Compiled regex patterns (from constants)
# ---------------------------------------------------------------------------
ssh_fail_pattern = re.compile(SSH_FAIL_PATTERN)
ssh_accept_pattern = re.compile(SSH_ACCEPT_PATTERN)
web_conn_pattern = re.compile(WEB_CONN_PATTERN)
web_fail_pattern = re.compile(WEB_FAIL_PATTERN)
web_exploit_pattern = re.compile(WEB_EXPLOIT_PATTERN)
sudo_pattern = re.compile(SUDO_PATTERN)
firewall_pattern = re.compile(FIREWALL_PATTERN)


# ---------------------------------------------------------------------------
# Log parser
# ---------------------------------------------------------------------------

def parse_log_line(line: str) -> dict | None:
    """Parse a single syslog line and return a JSON-serialisable dict."""
    line = line.strip()
    if not line:
        return None

    parts = line.split(" ", 5)
    if len(parts) < 6:
        return None

    timestamp = " ".join(parts[0:3])
    host = parts[3]
    msg = parts[5]

    # --- SSH FAILED ---
    m = ssh_fail_pattern.search(line)
    if m:
        user, ip, port = m.groups()
        geo = get_geoip_details(ip)
        is_blocked = ip in blocked_ips
        return {
            "timestamp": timestamp, "host": host, "service": "sshd",
            "ip": ip, "user": user, "port": port,
            "status": "BLOCKED" if is_blocked else "FAILURE",
            "message": f"Failed password attempt for user '{user}'",
            "threat_level": "Mitigated" if is_blocked else "Medium",
            "country": geo["country"], "cc": geo["cc"],
            "lat": geo["lat"], "lon": geo["lon"],
        }

    # --- SSH ACCEPTED ---
    m = ssh_accept_pattern.search(line)
    if m:
        user, ip, port = m.groups()
        geo = get_geoip_details(ip)
        is_local = geo["cc"] == "LAN" or ip == "127.0.0.1"
        return {
            "timestamp": timestamp, "host": host, "service": "sshd",
            "ip": ip, "user": user, "port": port,
            "status": "SUCCESS",
            "message": f"Successful login for user '{user}'",
            "threat_level": "Low" if is_local else "Critical",
            "country": geo["country"], "cc": geo["cc"],
            "lat": geo["lat"], "lon": geo["lon"],
        }

    # --- WEB FAIL LOGIN ---
    m = web_fail_pattern.search(line)
    if m:
        ip, user = m.groups()
        geo = get_geoip_details(ip)
        is_blocked = ip in blocked_ips
        return {
            "timestamp": timestamp, "host": host, "service": "web-server",
            "ip": ip, "user": user,
            "status": "BLOCKED" if is_blocked else "FAILURE",
            "message": f"Web login failure for account '{user}'",
            "threat_level": "Mitigated" if is_blocked else "Low",
            "country": geo["country"], "cc": geo["cc"],
            "lat": geo["lat"], "lon": geo["lon"],
        }

    # --- WEB EXPLOIT ---
    m = web_exploit_pattern.search(line)
    if m:
        exploit_type, ip, uri = m.groups()
        geo = get_geoip_details(ip)
        is_blocked = ip in blocked_ips
        return {
            "timestamp": timestamp, "host": host, "service": "web-server",
            "ip": ip,
            "status": "BLOCKED" if is_blocked else "ATTACK",
            "message": f"{exploit_type} on '{uri}'",
            "threat_level": "Mitigated" if is_blocked else "High",
            "country": geo["country"], "cc": geo["cc"],
            "lat": geo["lat"], "lon": geo["lon"],
        }

    # --- WEB NORMAL CONNECT ---
    m = web_conn_pattern.search(line)
    if m:
        ip, req = m.groups()
        geo = get_geoip_details(ip)
        return {
            "timestamp": timestamp, "host": host, "service": "web-server",
            "ip": ip,
            "status": "SUCCESS",
            "message": f"HTTP request: '{req}'",
            "threat_level": "Low",
            "country": geo["country"], "cc": geo["cc"],
            "lat": geo["lat"], "lon": geo["lon"],
        }

    # --- SUDO ---
    m = sudo_pattern.search(line)
    if m:
        user, target_user, cmd = m.groups()
        geo = get_geoip_details("192.168.1.100")
        return {
            "timestamp": timestamp, "host": host, "service": "sudo",
            "ip": "192.168.1.100", "user": user,
            "status": "SYSTEM",
            "message": f"User '{user}' executed command as '{target_user}': {cmd}",
            "threat_level": "Medium" if any(k in cmd for k in ("restart", "stop", "iptables")) else "Low",
            "country": geo["country"], "cc": geo["cc"],
            "lat": geo["lat"], "lon": geo["lon"],
        }

    # --- FIREWALL ---
    m = firewall_pattern.search(line)
    if m:
        action, ip = m.groups()
        geo = get_geoip_details(ip)
        return {
            "timestamp": timestamp, "host": host, "service": "custom-firewall",
            "ip": ip,
            "status": "SYSTEM",
            "message": f"{action}: Firewall rule applied to host {ip}",
            "threat_level": "Low",
            "country": geo["country"], "cc": geo["cc"],
            "lat": geo["lat"], "lon": geo["lon"],
        }

    # --- Fallback ---
    return {
        "timestamp": timestamp, "host": host, "service": "system",
        "ip": "N/A", "status": "SYSTEM", "message": msg,
        "threat_level": "Low",
        "country": "Unknown", "cc": "Unknown", "lat": 0, "lon": 0,
    }


# ---------------------------------------------------------------------------
# Rate-limit helper
# ---------------------------------------------------------------------------

def _check_rate_limit(client_ip: str) -> bool:
    """Return True if the client is within the rate limit, False otherwise."""
    now = time.time()
    record = _rate_limit_store.get(client_ip)
    if record is None or (now - record["ts"]) > RATE_LIMIT_WINDOW_SECONDS:
        _rate_limit_store[client_ip] = {"ts": now, "n": 1}
        return True
    record["n"] += 1
    return record["n"] <= RATE_LIMIT_MAX_REQUESTS


# ---------------------------------------------------------------------------
# HTTP handler
# ---------------------------------------------------------------------------

class SOCDashboardRequestHandler(BaseHTTPRequestHandler):

    def log_message(self, format, *args):
        # Silence default access-log spam
        pass

    # --- helpers ---

    def send_json(self, data: dict | list, status: int = 200) -> None:
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', 'http://localhost:8080')
        self.send_header('Cache-Control', 'no-store, no-cache, must-revalidate')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode('utf-8'))

    def _is_safe_path(self, normalized: str) -> bool:
        """FIX SEC-06: resolve against BASE_DIR to prevent traversal."""
        resolved = os.path.realpath(os.path.join(BASE_DIR, normalized.lstrip('/')))
        return resolved.startswith(os.path.realpath(BASE_DIR))

    # --- CORS preflight ---

    def do_OPTIONS(self) -> None:
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', 'http://localhost:8080')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()

    # --- GET ---

    def do_GET(self) -> None:
        normalized_path = os.path.normpath(self.path)

        if not self._is_safe_path(normalized_path):
            self.send_error(400, "Bad Request: Invalid Path")
            return

        if normalized_path in ("/", "/index.html"):
            if not os.path.exists(INDEX_HTML_PATH):
                self.send_error(404, "index.html not found")
                return
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.end_headers()
            with open(INDEX_HTML_PATH, 'rb') as f:
                self.wfile.write(f.read())

        elif normalized_path == "/mitigation_report.json":
            report_path = os.path.join(BASE_DIR, 'mitigation_report.json')
            if not os.path.exists(report_path):
                self.send_json({})
                return
            self.send_response(200)
            self.send_header('Content-Type', 'application/json; charset=utf-8')
            self.send_header('Access-Control-Allow-Origin', 'http://localhost:8080')
            self.end_headers()
            with open(report_path, 'rb') as f:
                self.wfile.write(f.read())

        elif normalized_path == "/api/logs":
            with log_lock:
                try:
                    with open(LOG_FILE_PATH, 'r') as f:
                        lines = f.readlines()
                except Exception as e:
                    self.send_json({"error": f"Failed to read logs: {e}"}, 500)
                    return

            parsed = []
            for line in reversed(lines):
                p = parse_log_line(line)
                if p:
                    parsed.append(p)
            self.send_json(parsed)

        elif normalized_path == "/api/stats":
            with log_lock:
                try:
                    with open(LOG_FILE_PATH, 'r') as f:
                        lines = f.readlines()
                except Exception as e:
                    self.send_json({"error": f"Failed to read logs: {e}"}, 500)
                    return

            parsed_list = [p for line in lines if (p := parse_log_line(line))]

            total_alerts = len(parsed_list)
            failed_logins = sum(
                1 for p in parsed_list
                if p["status"] in ("FAILURE", "BLOCKED") and "Failed" in p["message"]
            )
            successful_logins = sum(
                1 for p in parsed_list
                if p["status"] == "SUCCESS" and "Successful" in p["message"]
            )
            total_logins = failed_logins + successful_logins
            success_rate = round(successful_logins / total_logins * 100, 1) if total_logins > 0 else 100.0

            threat_distribution = {"Low": 0, "Medium": 0, "High": 0, "Critical": 0, "Mitigated": 0}
            top_ips_tracker: dict[str, int] = {}

            for p in parsed_list:
                threat_distribution[p["threat_level"]] = threat_distribution.get(p["threat_level"], 0) + 1
                if p["ip"] not in ("127.0.0.1", "192.168.1.100", "192.168.1.101", "N/A"):
                    top_ips_tracker[p["ip"]] = top_ips_tracker.get(p["ip"], 0) + 1

            sorted_ips = sorted(top_ips_tracker.items(), key=lambda x: x[1], reverse=True)[:5]
            formatted_top_ips = [
                {"ip": ip, "count": cnt, "location": get_geoip_details(ip)["country"], "cc": get_geoip_details(ip)["cc"]}
                for ip, cnt in sorted_ips
            ]

            self.send_json({
                "total_alerts": total_alerts,
                "failed_logins": failed_logins,
                "blocked_ips_count": len(blocked_ips),
                "success_rate": success_rate,
                "threat_level_distribution": threat_distribution,
                "top_ips": formatted_top_ips,
                "blocked_ips": list(blocked_ips),
            })

        else:
            self.send_error(404, "Endpoint not found")

    # --- POST ---

    def do_POST(self) -> None:
        normalized_path = os.path.normpath(self.path)

        if normalized_path != "/api/block":
            self.send_error(404, "Endpoint not found")
            return

        content_length = int(self.headers.get('Content-Length', 0))

        if content_length == 0:
            self.send_json({"error": "Missing payload"}, 400)
            return

        # FIX SEC-07: cap body size to prevent memory abuse
        if content_length > MAX_REQUEST_BODY_BYTES:
            self.send_json({"error": "Payload too large"}, 413)
            return

        try:
            body = self.rfile.read(content_length)
            data = json.loads(body.decode('utf-8'))
        except Exception as e:
            self.send_json({"error": f"Invalid JSON payload: {e}"}, 400)
            return

        ip = data.get('ip')
        action = data.get('action', 'block')

        # FIX SEC-03: never trust X-Forwarded-For without a reverse proxy
        client_ip = self.client_address[0]
        if not _check_rate_limit(client_ip):
            self.send_json({"error": "Rate limit exceeded. Try later."}, 429)
            return

        # FIX SEC-05: explicit None check before validation
        if not ip:
            self.send_json({"error": "Missing 'ip' field"}, 400)
            return

        # Strict IP validation via ipaddress module
        try:
            ipaddress.ip_address(ip)
        except (ValueError, TypeError):
            self.send_json({"error": "Invalid IP address format"}, 400)
            return

        # Safety: never block loopback / local admin
        if ip in ("127.0.0.1", "192.168.1.100") and action == 'block':
            self.send_json({"error": "Blocking admin loopback/local interfaces is prohibited"}, 400)
            return

        with log_lock:
            ts = time.strftime("%b %d %H:%M:%S")
            pid = random.randint(1000, 9999)

            if action == 'block':
                if ip in blocked_ips:
                    self.send_json({"status": "already blocked", "ip": ip})
                    return
                blocked_ips.add(ip)
                log_line = f"{ts} soc-server custom-firewall[{pid}]: BLOCKED IP: {ip} added to iptables active rules.\n"

            elif action == 'unblock':
                if ip not in blocked_ips:
                    self.send_json({"status": "not blocked", "ip": ip})
                    return
                blocked_ips.discard(ip)
                log_line = f"{ts} soc-server custom-firewall[{pid}]: UNBLOCKED IP: {ip} added to iptables active rules.\n"

            else:
                self.send_json({"error": "Invalid action, must be 'block' or 'unblock'"}, 400)
                return

            try:
                with open(LOG_FILE_PATH, 'a') as f:
                    f.write(log_line)
            except Exception as e:
                self.send_json({"error": f"Failed to update logs: {e}"}, 500)
                return

        self.send_json({"status": "success", "action": action, "ip": ip})


# ---------------------------------------------------------------------------
# Log Simulator (background thread)
# ---------------------------------------------------------------------------

def log_simulator_worker() -> None:
    """Append realistic syslog events every 3–6 s."""
    print("[Threat Simulator] Background threat thread active.")

    attacker_ips = [
        "195.133.40.12", "45.143.203.11", "91.241.19.82",
        "82.102.23.4", "212.102.33.15", "114.119.160.10", "81.2.222.12",
    ]
    local_ips = ["192.168.1.100", "192.168.1.101"]
    ssh_users = ["root", "admin", "developer", "guest", "ubuntu", "postgres", "mysql"]
    web_users = ["admin", "administrator", "manager", "support", "test"]
    queries = [
        "users?id=1%27%20OR%201%3D1",
        "search?q=%3Cscript%3Ealert(1)%3C/script%3E",
        "admin/upload.php", "config.php.bak",
        "etc/passwd?method=traversal",
    ]
    sudo_commands = [
        "/usr/bin/systemctl restart nginx",
        "/usr/sbin/iptables -L -n",
        "/usr/bin/tail -n 100 /var/log/auth.log",
        "/usr/bin/apt-get update",
    ]

    while True:
        try:
            time.sleep(random.uniform(3.0, 6.0))

            # Rotate log if too large
            with log_lock:
                try:
                    if os.path.exists(LOG_FILE_PATH):
                        with open(LOG_FILE_PATH, 'r') as f:
                            lines = f.readlines()
                        if len(lines) > 600:
                            with open(LOG_FILE_PATH, 'w') as f:
                                f.writelines(lines[-150:])
                                f.write(f'{time.strftime("%b %d %H:%M:%S")} soc-server custom-firewall[1111]: '
                                        f'SYSTEM: Rotated mock log file, maintaining active stats.\n')
                except Exception as e:
                    print(f"[Threat Simulator] Log rotation error: {e}")

            # Choose event
            event_type = random.choices(
                population=["ssh_fail", "ssh_success", "web_fail", "web_exploit", "web_success", "sudo"],
                weights=[40, 10, 20, 15, 10, 5],
                k=1,
            )[0]

            ts = time.strftime("%b %d %H:%M:%S")
            pid = random.randint(10000, 30000)
            log_line = ""

            if event_type == "ssh_fail":
                ip = random.choice(attacker_ips)
                user = random.choice(ssh_users)
                port = random.randint(30000, 65000)
                invalid = "invalid user " if random.random() > 0.5 else ""
                log_line = f"{ts} soc-server sshd[{pid}]: Failed password for {invalid}{user} from {ip} port {port} ssh2\n"

            elif event_type == "ssh_success":
                if random.random() > 0.85:
                    ip = random.choice(attacker_ips)
                    user = "root"
                else:
                    ip = random.choice(local_ips)
                    user = "sahil"
                port = random.randint(30000, 65000)
                log_line = f"{ts} soc-server sshd[{pid}]: Accepted password for {user} from {ip} port {port} ssh2\n"

            elif event_type == "web_fail":
                ip = random.choice(attacker_ips)
                user = random.choice(web_users)
                log_line = f'{ts} soc-server web-server[{pid}]: FAIL LOGIN: Client "{ip}", user "{user}"\n'

            elif event_type == "web_exploit":
                ip = random.choice(attacker_ips)
                query = random.choice(queries)
                if "passwd" in query:
                    exploit_type = "Directory Traversal attempt detected"
                elif "script" in query:
                    exploit_type = "XSS exploit attempt detected"
                elif "OR" in query:
                    exploit_type = "SQL Injection attempt detected"
                else:
                    exploit_type = "Malicious request signature detected"
                log_line = f"{ts} soc-server web-server[{pid}]: WARNING: {exploit_type} from {ip} - Uri: /api/{query}\n"

            elif event_type == "web_success":
                ip = random.choice(attacker_ips + local_ips)
                log_line = f'{ts} soc-server web-server[{pid}]: CONNECT: Client "{ip}" Request: "GET /static/dashboard.js HTTP/1.1"\n'

            elif event_type == "sudo":
                cmd = random.choice(sudo_commands)
                log_line = f"{ts} soc-server sudo[{pid}]: sahil : TTY=pts/0 ; PWD=/home/sahil ; USER=root ; COMMAND={cmd}\n"

            if log_line:
                with log_lock:
                    try:
                        with open(LOG_FILE_PATH, 'a') as f:
                            f.write(log_line)
                    except Exception as e:
                        print(f"[Threat Simulator] Write error: {e}")

        except Exception as e:
            # Ensure the simulator thread never crashes
            print(f"[Threat Simulator] Unexpected error: {e}")


# ---------------------------------------------------------------------------
# Server entry-point
# ---------------------------------------------------------------------------

def run_server(port: int = 8080) -> None:
    sim_thread = threading.Thread(target=log_simulator_worker, daemon=True)
    sim_thread.start()

    server_address = ('', port)
    httpd = HTTPServer(server_address, SOCDashboardRequestHandler)

    # Graceful shutdown on SIGTERM
    def _shutdown(signum, frame):
        print("\n[Server] Received signal, shutting down...")
        httpd.shutdown()

    signal.signal(signal.SIGTERM, _shutdown)

    print(f"\n========================================================")
    print(f"  Next-Gen SOC Threat Dashboard Server Running          ")
    print(f"  Address: http://localhost:{port}                      ")
    print(f"========================================================\n")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[Server] Shutting down.")
    finally:
        httpd.server_close()


if __name__ == '__main__':
    run_server()
