# 🛡️ Linux Web Server Adversary Emulation with Detection & Prevention Lab

A hands-on Security Operations Center (SOC) lab designed to simulate real-world web attacks, detect them using open-source security tooling, and apply post-detection response actions in a controlled Linux environment.

This project demonstrates end-to-end blue-team workflows — from log ingestion and threat detection to alert correlation and semi-automated response.

## 🧱 Lab Architecture

Machines Used
Role	OS	Purpose
SOC Server	Ubuntu	Centralized detection, correlation, alerting, and response
Web Server	Ubuntu	Apache web server + Suricata IDS/IPS + Wazuh agent
Attacker VM	Linux	Controlled adversary simulation (recon & web attacks)

## 🔁 End-to-End SOC Flow

```
Attacker VM
   ↓
Web Server (Apache + Suricata)
   ↓
Wazuh Agent (log collection)
   ↓
SOC Server (Wazuh Manager)
   ↓
Detection Rules & Decoders
   ↓
Alert Correlation (MITRE mapped)
   ↓
Active Response (Semi-Automated IPS)
```

### 🔧 Tools & Technologies

Apache HTTP Server – Targeted web service

Suricata – Network IDS / IPS (signature-based)

Wazuh – Host-based detection, correlation, and response

OpenSearch (Wazuh Indexer) – Alert indexing

Wazuh Dashboard – SOC visibility & investigation

Custom Rules & Decoders – Project-specific detections

Linux Bash Scripts – Semi-automated prevention actions

### 📌 Project Phases (Step-by-Step)

## Phase 1 – Baseline & Environment Setup

Deployed Apache web server on Ubuntu

Verified normal web traffic behavior

Established baseline logs before attacks

Installed Wazuh agent on web server

Confirmed agent-to-manager communication

✔️ Goal: Understand “normal” before detecting “malicious”

Phase 2 – Network Visibility with Suricata (IDS Mode)

Installed Suricata on the web server

Enabled IDS mode to monitor all incoming traffic

Validated rule loading and event generation

Confirmed alerts in eve.json

✔️ Goal: Detect reconnaissance and web-based attacks

Phase 3 – Centralized Log Collection (Wazuh)

Configured Wazuh agent to collect:

Apache access & error logs

Suricata eve.json events

Forwarded logs securely to SOC server

Verified log ingestion using Wazuh logcollector

✔️ Goal: Single pane of glass for host + network logs

Phase 4 – Custom Decoders (SOC Intelligence Layer)

Created custom decoders on the SOC server to correctly parse:

Suricata JSON alerts

Apache HTTP access patterns

📁 Files:

/var/ossec/etc/decoders/suricata_decoders.xml
/var/ossec/etc/decoders/apache_decoders.xml


✔️ Goal: Teach SOC how to “understand” raw logs

Phase 5 – Custom Detection Rules

Developed SOC-specific rules mapped to real attack behavior:

Network reconnaissance (Nmap)

Suspicious HTTP requests

Enumeration and abnormal access patterns

📁 Files:

/var/ossec/etc/rules/suricata_rules.xml
/var/ossec/etc/rules/apache_rules.xml


✔️ Goal: Turn decoded events into actionable alerts

Phase 6 – Alert Correlation & MITRE ATT&CK Mapping

Correlated Suricata + Apache + host logs

Mapped detections to MITRE ATT&CK techniques

Validated alert indexing in OpenSearch

Verified visibility in Wazuh Dashboard

✔️ Goal: Explain attacks in attacker-centric language

Phase 7 – Semi-Automated Prevention (IPS-Style Response)

Implemented post-detection response actions:

Configured Wazuh Active Response

Added whitelist protections to avoid self-lockout

Triggered response scripts after high-confidence alerts

Demonstrated detection → response workflow

📁 Modified file:

/var/ossec/etc/ossec.conf


✔️ Goal: Move from IDS → Preventive control

🔐 SOC Server – Configuration Changes Summary
Modified Files

/var/ossec/etc/ossec.conf

Enabled active response

Added whitelist for SOC safety

/var/ossec/etc/decoders/

suricata_decoders.xml

apache_decoders.xml

/var/ossec/etc/rules/

suricata_rules.xml

apache_rules.xml

Validation Commands
sudo /var/ossec/bin/wazuh-analysisd -t
sudo ls /var/ossec/logs/alerts


✔️ Confirms SOC logic is live and stable

📊 SOC Validation Evidence

Suricata alerts detected Nmap scans

Apache logs correlated with network activity

Alerts indexed into OpenSearch

Visible in Wazuh Dashboard

Active response logic triggered safely

🎯 What This Project Demonstrates

Real SOC detection workflows

Host + network correlation

Custom detection engineering

Safe, semi-automated prevention

Industry-aligned blue-team practices

🚀 Why This Project Stands Out

✔️ Not a copy-paste lab
✔️ Custom rules & decoders
✔️ Detection → Response pipeline
✔️ SOC-ready explanation
✔️ Interview-ready depth

🧠 Future Enhancements (Optional)

Full Suricata IPS inline mode

Automated response tuning

Atomic Red Team integration

Threat intelligence enrichment
