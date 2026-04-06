# 🔐 SSH Brute Force Detection with Splunk 

![Project Status](https://img.shields.io/badge/Status-Complete-green)
![SIEM](https://img.shields.io/badge/SIEM-Splunk-orange)
![Attack Tool](https://img.shields.io/badge/Tools-Hydra%20|%20Medusa%20)
![ATT&CK](https://img.shields.io/badge/MITRE-T1110.001%20|%20T1003.008%20|%20T1548-blue)

## 📌 Project Overview

A full end-to-end home lab project simulating an SSH brute force attack chain and building real-time detection using Splunk SIEM. This project covers the complete attacker workflow — from reconnaissance to credential theft — and builds corresponding detections for each stage.

---

## 🎯 Objectives

- Simulate a realistic SSH brute force attack in a controlled lab environment
- Understand how auth.log captures authentication events
- Ingest logs into Splunk and write SPL detection queries
- Build threshold-based alerts for credential abuse
- Detect the full attack chain: recon → brute force → compromise → privilege escalation → hash theft
- Map detections to MITRE ATT&CK framework

---

## 🖥️ Lab Environment

| VM | OS | Role | IP |
|---|---|---|---|
| Attacker | Kali Linux | Attack machine | 192.168.x.x |
| Attacker | Parrot OS | Attack machine | 192.168.x.x |
| Victim | Ubuntu 22.04 | Target / Log source | 192.168.x.x |
| SIEM | Splunk (on Ubuntu) | Log ingestion & detection | 192.168.x.x:8000 |

**Network:** Host-Only Adapter (VMs communicate internally)

---

## 🛠️ Tools Used

| Tool | Category | Purpose |
|---|---|---|
| Nmap | Recon | Port scanning / service discovery |
| Hydra | Online Brute Force | SSH password attack |
| Medusa | Online Brute Force | SSH password attack (comparison) |
| Splunk | SIEM | Log ingestion, detection, alerting |
| auditd | Linux Auditing | File access monitoring |

---

## ⚔️ Attack Chain

```
[Kali - Attacker]
      |
      |-- 1. Nmap Recon ---------> Discover SSH on port 22
      |
      |-- 2. Hydra/Medusa -------> SSH Brute Force attack
      |                            Generate failed auth events
      |
      |-- 3. SSH Login ----------> Successful login (testuser)
      |                            Accepted password event logged
      |
      |-- 4. sudo attempt -------> Unauthorized sudo = blocked + logged
      |
      |-- 5. /etc/shadow read ---> Hash theft after sudo misconfiguration
```

---

## 📋 Step-by-Step Walkthrough

### Phase 1 — Lab Setup

**Ubuntu (Victim) — Enable SSH:**
```bash
sudo apt install openssh-server -y
sudo systemctl start ssh
sudo adduser testuser   # weak password: password123
```

**Splunk — Install and configure:**
```bash
sudo dpkg -i splunk.deb
sudo /opt/splunk/bin/splunk start --accept-license
# Add /var/log/auth.log as data input (sourcetype: linux_secure)
```

---

### Phase 2 — Reconnaissance

```bash
# From Kali
nmap -sV -p 22 <ubuntu-ip>
```

**Result:** SSH open on port 22, OpenSSH version identified.

---

### Phase 3 — Brute Force Attack

**Wordlists used:**
```
usernames.txt: root, admin, testuser, ubuntu
passwords.txt: 123456, password, password123, admin, letmein, root
```

**Hydra:**
```bash
hydra -L usernames.txt -P passwords.txt ssh://<ubuntu-ip> -t 4 -v
```

**Medusa:**
```bash
medusa -h <ubuntu-ip> -U usernames.txt -P passwords.txt -M ssh -t 4 -f -v 6
```

**Result:** `testuser:password123` found by both tools.

---

### Phase 4 — Post-Compromise

```bash
# Login via SSH
ssh testuser@<ubuntu-ip>

# Attempt privilege escalation (blocked - logged)
sudo cat /etc/shadow   # → "not in sudoers" logged

# After sudo misconfiguration added via visudo:
sudo cat /etc/shadow   # → hashes retrieved

# Exfiltrate hashes
scp testuser@<ubuntu-ip>:/tmp/stolen_hashes.txt ~/
```
---

## 🔍 Splunk SPL Queries

### 1. All Failed SSH Logins
```spl
index=main sourcetype=linux_secure "Failed password"
| table _time, src_ip, user, host
```

### 2. Failed Attempts Per Source IP
```spl
index=main sourcetype=linux_secure "Failed password"
| rex "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats count as failed_attempts by src_ip
| sort - failed_attempts
```

### 3. Brute Force Threshold (>5 failures in 5 min)
```spl
index=main sourcetype=linux_secure "Failed password"
| rex "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| bucket _time span=5m
| stats count as attempts by _time, src_ip
| where attempts > 5
```

### 4. Successful Login After Failures (Compromise Detected)
```spl
index=main sourcetype=linux_secure ("Failed password" OR "Accepted password")
| rex "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| rex "for (?<user>\S+) from"
| stats count(eval(match(_raw,"Failed"))) as failures,
        count(eval(match(_raw,"Accepted"))) as successes by src_ip, user
| where failures > 3 AND successes > 0
```

### 5. Unauthorized Sudo Attempt
```spl
index=main sourcetype=linux_secure "not in sudoers"
| table _time, user, host, _raw
```

### 6. /etc/shadow Access (auditd)
```spl
index=main source="/var/log/audit/audit.log" "shadow"
| table _time, host, key, exe
```

### 7. Full Attack Timeline from Single IP
```spl
index=main (sourcetype=linux_secure OR source="/var/log/audit/audit.log")
| rex "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| search src_ip="<attacker-ip>"
| table _time, sourcetype, _raw
| sort _time
```

---

## 🚨 Alerts Configured in Splunk

| Alert Name | Trigger Condition | Severity |
|---|---|---|
| SSH Brute Force - 5+ Failures in 5 min | results > 0 every 5 min | High |
| Successful Login After Failures | results > 0 | Critical |
| Unauthorized Sudo Attempt | results > 0 | Medium |
| /etc/shadow Access Detected | results > 0 | Critical |

---

## 📊 Splunk Dashboard Panels

| Panel | Visualization |
|---|---|
| Failed Logins Over Time | Line Chart |
| Top Attacking IPs | Bar Chart |
| Brute Force Threshold Breaches | Table |
| Successful Login After Failures | Table (Critical) |
| Unauthorized Privilege Escalation | Table |
| /etc/shadow Access Attempts | Table |

---

## 🧩 MITRE ATT&CK Mapping

| Technique ID | Name | Detected By |
|---|---|---|
| T1110.001 | Brute Force: Password Guessing | Splunk auth.log alert |
| T1003.008 | OS Credential Dumping: /etc/shadow | auditd + Splunk |
| T1548 | Abuse Elevation Control Mechanism | sudo log + Splunk |
| T1041 | Exfiltration Over C2 Channel | SCP detection query |

---

## 📝 Sample Incident Report

```
=== INCIDENT REPORT ===
Date/Time:        [04/04/2026: 22.00 pm]
Analyst:          [Ojas Patil]
Severity:         Critical

Attack Summary:
  Attacker IP:    192.168.x.x (Kali)
  Attacker IP:    192.168.x.x (Parrot OS)
  Target IP:      192.168.x.x (Ubuntu)
  Method:         SSH Brute Force via Hydra/Medusa
  Result:         Successful login - testuser compromised

Timeline:
  HH:MM  - Nmap scan detected on port 22
  HH:MM  - Brute force started (50+ failed attempts)
  HH:MM  - Successful login: testuser
  HH:MM  - Unauthorized sudo attempt blocked & logged
  HH:MM  - /etc/shadow accessed after sudo misconfiguration

Alerts Fired:
  [x] SSH Brute Force - 5+ Failures in 5 min
  [x] Successful Login After Failures
  [x] Unauthorized Sudo Attempt
  [x] /etc/shadow Access Detected

Recommended Actions:
  1. Block attacker IP at firewall immediately
  2. Disable testuser account
  3. Rotate all passwords on affected system
  4. Patch sudo misconfiguration
  5. Escalate to L2 for forensic investigation
  6. Review all SCP/file transfer logs
```

---

## 💡 Key Learnings

- How SSH brute force attacks generate detectable patterns in auth.log
- Difference between online attacks (Hydra/Medusa) vs offline cracking (John/Hashcat)
- How to write SPL queries for real threat detection scenarios
- Importance of auditd for file-level monitoring beyond auth.log
- The critical pattern: **failures → success = confirmed compromise**
- How to map real attacks to MITRE ATT&CK framework

---

## 🔗 References

- [Splunk SPL Documentation](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference)
- [MITRE ATT&CK T1110](https://attack.mitre.org/techniques/T1110/001/)
- [MITRE ATT&CK T1003](https://attack.mitre.org/techniques/T1003/008/)
- [Hydra GitHub](https://github.com/vanhauser-thc/thc-hydra)
- [Medusa GitHub](https://www.kali.org/tools/medusa/)

---

## 👤 Author

**OJAS MILIND PATIL**
SOC Analyst L1 | Home Lab Enthusiast
[LinkedIn](https://linkedin.com/in/yourprofile) | [GitHub](https://github.com/yourprofile)

> ⚠️ **Disclaimer:** This project was conducted in an isolated home lab environment for educational purposes only. Never perform these techniques on systems you do not own or have explicit permission to test.

