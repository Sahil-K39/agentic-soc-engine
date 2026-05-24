"""agent_platform.py — Antigravity EDR Agent watcher."""
from __future__ import annotations

import os
import re
import json
import asyncio
import dotenv
from google.antigravity import Agent, LocalAgentConfig
from google.antigravity.hooks import policy

from constants import MITRE_ATTACK_DB, LOG_FILE_PATH, REPORT_FILE_PATH
from models import MitigationReport

# Load environment variables
dotenv.load_dotenv()


# ---------------------------------------------------------------------------
# Local rule-based fallback
# ---------------------------------------------------------------------------

def local_fallback_parse(line: str) -> MitigationReport | None:
    """Map a raw log line to a MitigationReport using keyword heuristics."""

    db: dict | None = None
    ip: str = "0.0.0.0"

    if "Failed password" in line:
        db = MITRE_ATTACK_DB["sshd_fail"]
        ip_match = re.search(r'from (\S+)', line)
        ip = ip_match.group(1) if ip_match else "0.0.0.0"

    elif "Accepted password" in line:
        ip_match = re.search(r'from (\S+)', line)
        ip = ip_match.group(1) if ip_match else "0.0.0.0"
        # Ignore local / loopback logins
        if ip.startswith("192.168.") or ip == "127.0.0.1":
            return None
        db = MITRE_ATTACK_DB["sshd_accept_external"]

    elif "FAIL LOGIN" in line:
        db = MITRE_ATTACK_DB["web_fail"]
        ip_match = re.search(r'Client "(\S+)"', line)
        ip = ip_match.group(1) if ip_match else "0.0.0.0"

    elif "SQL Injection" in line:
        db = MITRE_ATTACK_DB["web_sql"]
        ip_match = re.search(r'from (\S+)', line)
        ip = ip_match.group(1) if ip_match else "0.0.0.0"

    elif "Directory Traversal" in line:
        db = MITRE_ATTACK_DB["web_traversal"]
        ip_match = re.search(r'from (\S+)', line)
        ip = ip_match.group(1) if ip_match else "0.0.0.0"

    elif "sudo[" in line:                       # FIX BUG-03: match service prefix, not bare "sudo"
        db = MITRE_ATTACK_DB["sudo_abuse"]
        ip = "192.168.1.100"

    else:
        return None

    return MitigationReport(
        status="Active Threat",
        ip=ip,
        vector=db["vector"],
        mitre_id=db["mitre_id"],
        patch_command=f"iptables -A INPUT -s {ip} -j DROP",
    )


# ---------------------------------------------------------------------------
# Report persistence
# ---------------------------------------------------------------------------

def write_mitigation_report(report: MitigationReport) -> None:
    """Atomically write the mitigation report to disk."""
    tmp_path = REPORT_FILE_PATH + ".tmp"
    try:
        with open(tmp_path, 'w') as f:
            json.dump(report.model_dump(), f, indent=2)      # FIX BUG-01: .dict() → .model_dump()
        os.replace(tmp_path, REPORT_FILE_PATH)                # atomic rename
        print(f"[{report.ip}] Saved mitigation profile to mitigation_report.json.")
    except OSError as e:
        print(f"⚠️ Failed to write report: {e}")


# ---------------------------------------------------------------------------
# Log-line processor
# ---------------------------------------------------------------------------

async def process_log_line(line: str, security_analyst: Agent | None) -> None:
    """Analyse a single log line — via Agent first, then local fallback."""
    line = line.strip()
    if not line:
        return

    print(f"🔍 Analyzing log trigger: {line}")

    # Attempt Agent-based analysis
    if security_analyst is not None:
        try:
            prompt = (
                f"Analyze this log event immediately: '{line}'.\n"
                "Map it to its corporate MITRE ATT&CK technique and generate "
                "the mitigation patch command.\n\n"
                "Format response following the schema instructions.\n"
                "Attacker IP ('ip') should be parsed from the log line. "
                "If none is found, use '0.0.0.0'.\n"
                "Determine the attack vector (e.g. SSH Brute Force, SQL Injection, "
                "Web login failure, Directory Traversal).\n"
                "Select the closest MITRE ATT&CK technique ID and name "
                "(e.g. 'T1190 - Exploit Public-Facing Application' or "
                "'T1110 - Brute Force').\n"
                "Set 'patch_command' to 'iptables -A INPUT -s {ip} -j DROP' "
                "using the parsed IP.\n"
                "Set 'status' to 'Active Threat'."
            )
            response = await security_analyst.chat(prompt)
            data = await response.structured_output()
            if data:
                report = MitigationReport(**data)
                write_mitigation_report(report)
                return
        except Exception as e:
            print(f"⚠️ Agent error during analysis: {e}. Falling back to local rules...")

    # Fallback path
    fallback_report = local_fallback_parse(line)
    if fallback_report:
        write_mitigation_report(fallback_report)


# ---------------------------------------------------------------------------
# Main entry-point
# ---------------------------------------------------------------------------

TRIGGER_KEYWORDS = ["Failed password", "WARNING:", "FAIL LOGIN", "Accepted password"]


async def main() -> None:
    print("🛡️ Booting Antigravity Cyber Security platform...")

    api_key_configured = os.environ.get("GEMINI_API_KEY") is not None
    security_analyst: Agent | None = None

    if api_key_configured:
        try:
            print("🔑 GEMINI_API_KEY detected. Initializing Antigravity Agent...")  # FIX BUG-05: typo
            config = LocalAgentConfig(
                model="gemini-3.5-flash",
                response_schema=MitigationReport,
            )
            config.policies = [policy.allow_all()]
            security_analyst = Agent(config)
        except Exception as e:
            print(f"⚠️ Failed to configure Antigravity Agent: {e}. "
                  "Proceeding in local-fallback mode.")
    else:
        print("💡 GEMINI_API_KEY not configured. Running in local-fallback mode.")

    # FIX BUG-02: use async-with for guaranteed cleanup
    async def _run(agent: Agent | None) -> None:
        # Ingest last historical threat
        print("📂 Ingesting historical log data...")
        if os.path.exists(LOG_FILE_PATH):
            with open(LOG_FILE_PATH, 'r') as f:
                lines = f.readlines()
            for line in reversed(lines):
                if any(kw in line for kw in TRIGGER_KEYWORDS):
                    await process_log_line(line, agent)
                    break

        print("🛰️ Watching mock_auth.log for new security triggers...")
        file_size = os.path.getsize(LOG_FILE_PATH) if os.path.exists(LOG_FILE_PATH) else 0

        try:
            while True:
                await asyncio.sleep(1)
                if not os.path.exists(LOG_FILE_PATH):
                    continue

                current_size = os.path.getsize(LOG_FILE_PATH)
                if current_size > file_size:
                    with open(LOG_FILE_PATH, 'r') as f:
                        f.seek(file_size)
                        new_lines = f.readlines()

                    file_size = current_size
                    for line in new_lines:
                        if any(kw in line for kw in TRIGGER_KEYWORDS):
                            await process_log_line(line, agent)
                            await asyncio.sleep(2)
                elif current_size < file_size:
                    # File was rotated / truncated
                    file_size = current_size

        except KeyboardInterrupt:
            print("Shutting down watcher.")

    if security_analyst is not None:
        async with security_analyst:          # guaranteed __aexit__
            await _run(security_analyst)
    else:
        await _run(None)


if __name__ == "__main__":
    asyncio.run(main())
