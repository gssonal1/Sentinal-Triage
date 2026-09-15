#!/usr/bin/env python3
"""
SentinelTriage - AI-assisted SOC triage & auto-containment agent
------------------------------------------------------------------
- Streams live alerts from the Wazuh manager
- Scores severity and writes a plain-English analyst justification
  (free Google Gemini API, with an offline rule-based fallback)
- Auto-blocks high-severity attacker IPs with iptables (SOAR containment)
- Logs every decision with its reasoning (explainable triage)

RUN (needs root for iptables + docker; -E keeps your API key):
    sudo -E python3 triage.py
"""

import json
import subprocess
import os
import datetime
import requests

# ==================== CONFIG ====================
MANAGER_CONTAINER = "single-node-wazuh.manager-1"   # verified via docker ps
ALERTS_PATH       = "/var/ossec/logs/alerts/alerts.json"
BLOCK_LEVEL       = 12                    # auto-block if rule level >= 12 (rule 100002)
WATCH_RULES       = {"100001", "100002", "100003"}   # custom rules to watch
DECISION_LOG      = "triage_decisions.log"

# Google Gemini Configuration
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")
GEMINI_MODEL   = "gemini-3.5-flash"   # current free model endpoint
GEMINI_URL     = f"https://generativelanguage.googleapis.com/v1beta/models/{GEMINI_MODEL}:generateContent"
# ================================================

blocked_ips = set()

def extract(alert):
    """Extract required fields from raw Wazuh alert JSON payload."""
    rule  = alert.get("rule", {})
    data  = alert.get("data", {})
    agent = alert.get("agent", {})
    mitre = rule.get("mitre", {}).get("id", [])
    return {
        "rule_id": str(rule.get("id", "")),
        "level":   int(rule.get("level", 0)),
        "desc":    rule.get("description", ""),
        "srcip":   data.get("srcip", ""),
        "agent":   agent.get("name", ""),
        "mitre":   ", ".join(mitre) if isinstance(mitre, list) else str(mitre),
    }

def ai_justify(info):
    """Request 2-sentence summary from Gemini API; fallback to offline logic if unreachable."""
    if not GEMINI_API_KEY:
        return offline_justify(info)
    prompt = (
        "You are a SOC Tier-1 analyst. In 2 sentences, plainly explain why this "
        "security alert matters and recommend ONE containment action.\n"
        f"Alert: {info['desc']}\nRule level: {info['level']}\n"
        f"MITRE: {info['mitre']}\nSource IP: {info['srcip']}\nAgent: {info['agent']}"
    )
    try:
        r = requests.post(
            GEMINI_URL,
            headers={"x-goog-api-key": GEMINI_API_KEY, "Content-Type": "application/json"},
            json={"contents": [{"parts": [{"text": prompt}]}]},
            timeout=30,
        )
        r.raise_for_status()
        return r.json()["candidates"][0]["content"]["parts"][0]["text"].strip()
    except Exception as e:
        return offline_justify(info) + f"   [AI offline: {e}]"

def offline_justify(info):
    """Rule-based offline explanation engine."""
    templates = {
        "100002": ("Successful login from an IP that was just brute forcing - a LIKELY "
                   "account compromise. Action: block the source IP and disable the account."),
        "100001": ("Repeated failed logins from one IP - a brute-force attempt in progress. "
                   "Action: monitor; block if it escalates to a successful login."),
        "100003": ("A new user account was created - possible attacker persistence/backdoor. "
                   "Action: verify the account and remove it if unauthorized."),
    }
    return templates.get(
        info["rule_id"],
        f"High-severity alert (level {info['level']}). Action: investigate the source and contain if malicious."
    )

def block_ip(ip):
    """SOAR containment: drop all traffic from attacker IP using iptables."""
    if not ip or ip in blocked_ips:
        return False
    try:
        subprocess.run(["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"], check=True)
        blocked_ips.add(ip)
        return True
    except Exception as e:
        print(f"[!] Could not block {ip}: {e}")
        return False

def log_decision(info, justification, blocked):
    stamp = datetime.datetime.now().isoformat(timespec="seconds")
    entry = (f"{stamp} | rule={info['rule_id']} level={info['level']} "
             f"src={info['srcip'] or 'n/a'} mitre={info['mitre'] or 'n/a'} blocked={blocked}\n"
             f"    WHY: {justification}\n")
    print(entry)
    with open(DECISION_LOG, "a") as f:
        f.write(entry)

def handle(alert):
    info = extract(alert)
    if info["rule_id"] not in WATCH_RULES and info["level"] < BLOCK_LEVEL:
        return
    justification = ai_justify(info)
    blocked = False
    if info["level"] >= BLOCK_LEVEL and info["srcip"]:
        blocked = block_ip(info["srcip"])
    log_decision(info, justification, blocked)

def main():
    print("[*] SentinelTriage running. Watching for alerts... (Ctrl+C to stop)\n")
    cmd = ["docker", "exec", MANAGER_CONTAINER, "tail", "-n", "0", "-f", ALERTS_PATH]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True)
    try:
        for line in proc.stdout:
            line = line.strip()
            if not line:
                continue
            try:
                alert = json.loads(line)
            except json.JSONDecodeError:
                continue
            handle(alert)
    except KeyboardInterrupt:
        print("\n[*] Stopped.")
    finally:
        proc.terminate()

if __name__ == "__main__":
    main()
