🛡 SentinelTriage: AI-Assisted SOC Detection & Auto-Containment

A hands-on Blue-Team lab that detects attacks in real time, maps them to MITRE ATT&CK, and automatically contains the attacker with an LLM-assisted triage layer that explains each decision in plain English.

⚙ What this is: a self-contained detection-engineering lab built to develop and validate detections the same way it's done in industry simulate attacks, write detections, confirm they fire, automate the response.
*It is an educational environment, not a production deployment.*

📌 The problem it addresses:
Modern SOCs are flooded with alerts (alert fatigue), and slow triage means slow response. 
This project demonstrates a small "AI Tier-1 analyst" that reads alerts, prioritises the ones that matter, explains why, and auto-contains confirmed threats.

🧱 Architecture
   ┌──────────────┐   simulated attacks 
(isolated network)   
┌────────────────────────┐
   │   KALI VM (attacker)    │ 
─────────────────────────────────────
───▶│   UBUNTU "Defender"    │
   │  (defender)  │                           
│  ┌──────────────────┐  │
   └──────────────┘                        
│  │ Wazuh SIEM       │  │
                                              
│  │ (Docker)         │  │
                                              
│  └────────┬─────────┘  │
                                              
│           │ alerts.json │
                                              
│  ┌────────▼─────────┐  │
                                              
│  │ triage.py        │  │
                                              
│  │ LLM triage +     │  │
                                              
│  │ iptables block   │  │
                                              
│  └──────────────────┘  │
                                              
└────────────────────────┘


🔍 Detections (mapped to MITRE ATT&CK)
Rule ID                Detection                                                    MITRE Technique
100001                 SSH brute force(repeated failures,same IP)                   T1110 Brute Force
100002                 Successful login after brute force (likelycompromise)        T1110 Brute Force
100003                 New local user account created                               T1136.001 Create Account
FIM 550/554            SSH authorized_keys tampering                                T1098.004 SSH Authorized Keys

Rule 100002 is a custom correlation rule — it fires only when a login succeeds from an IP that was just brute forcing, flagging a probable compromise instead of routine noise.

🤖 AI-assisted triage & auto containment (SOAR):
triage.py streams Wazuh alerts live and, for each relevant alert:
1. Generates a plain-English analyst justification using an LLM (Google Gemini), with a rule-based fallback so it works offline.
2. Auto-blocks the attacker's IP with iptables, only on confirmed compromise (rule level ≥ 12), not on noisy brute-force attempts, to avoid false positive self lockout.
self-lockout.
3. Logs every decision with its reasoning(triage_decisions.log) for auditability.

Design decision: containing on confirmed compromise rather than on every failed login is deliberate, it mirrors how real SOCs avoid self-inflicted denial of service.


🚀 Deployment (summary)
Full step-by-step is in docs/. High-level:
1. Environment: Kali, Ubuntu, and Metasploitable VMs on an isolated VMware network (Host-Only / NAT; never Bridged).
2. SIEM: deploy Wazuh single-node via Docker on Ubuntu; enrol the Ubuntu host as a self-monitoring agent.
3. Detections: load detections/local_rules.xml into the manager, restart.
4. Attack: run the simulations in attacks/ATTACK_PLAYBOOK.md from Kali.
5. Automate: sudo -E python3 soar/triage.py,then re-run the attack and watch the attacker IP get auto-blocked

🎓 Key Security Learnings
1. Correlation beats single events. Detecting success after brute force is far higher-signal than counting failed logins.
2. Host vs network visibility. A host agent doesn't see raw network scans a real SOC also needs network detection (e.g., Suricata). Knowing your blind spots matters.
3. Automate responsibly. Auto-containment must be scoped to high-confidence events or it becomes a self-inflicted outage.
4. Change the defaults. Default SIEM credentials were changed on first login.
5. MITRE ATT&CK as a shared language makes detections and reports readable to any analyst.

🛠 Tech Stack
Wazuh · Docker · Kali Linux · Ubuntu · Python 3 ·iptables · Google Gemini API ·MITRE ATT&CK · VMware Workstation

⚠ Disclaimer
This project runs entirely within an isolated lab against systems I own. 
All attacks are simulated for detection-testing and educational purposes only.
Do not use these techniques against systems you do not own or have explicit permission to test.

👤 Author
G S SONAL
Final Year CSE (Cyber Security)
SOC ANALYST
