# 🛡️ Threat Hunt Report: The Buyer

---

## 📌 Executive Summary

On January 27, 2026, an Akira ransomware affiliate attacked Ashford Sterling Recruitment using pre-staged access from a prior compromise. The attacker disabled Windows Defender, dumped credentials from LSASS, moved laterally to a domain server, and encrypted files across two hosts. Data was exfiltrated before encryption. The ransomware binary was then deleted to slow forensic recovery. This investigation was completed 47 days after the incident using Azure Log Analytics as the sole data source, as MDE Advanced Hunting logs had already expired.

---

## 🎯 Hunt Objectives

- Reconstruct the full attack chain from initial access through ransomware deployment
- Identify attacker tools, infrastructure, and techniques across both compromised hosts
- Correlate attacker behavior to MITRE ATT&CK techniques
- Document detection gaps and provide actionable recommendations for defenders

---

## 🧭 Scope & Environment

- **Organization:** Ashford Sterling Recruitment (fictional)
- **Platform:** SancLogic Cyber Range
- **SIEM:** Microsoft Sentinel
- **Query Platform:** Azure Log Analytics (LAW-Cyber-Range workspace)
- **Data Sources:** DeviceProcessEvents, DeviceFileEvents, DeviceNetworkEvents, DeviceRegistryEvents, DeviceEvents, DeviceLogonEvents
- **Incident Date:** 2026-01-27
- **Investigation Date:** 2026-03-15 to 2026-03-16
- **Hosts Compromised:** as-pc2, as-srv
- **Compromised User:** david.mitchell

---

## 📚 Table of Contents

- [🧠 Hunt Overview](#-hunt-overview)
- [⚔️ Attack Timeline](#%EF%B8%8F-attack-timeline)
- [🧬 MITRE ATT&CK Summary](#-mitre-attck-summary)
- [🔍 Flag Analysis](#-flag-analysis)
  - [🚩 Flag 1 – Defense Evasion via Registry Modification](#-flag-1--defense-evasion-via-registry-modification)
  - [🚩 Flag 2 – Defense Evasion via kill.bat](#-flag-2--defense-evasion-via-killbat)
  - [🚩 Flag 3 – Inhibit System Recovery via Shadow Copy Deletion](#-flag-3--inhibit-system-recovery-via-shadow-copy-deletion)
  - [🚩 Flag 4 – Credential Access via LSASS Named Pipe](#-flag-4--credential-access-via-lsass-named-pipe)
  - [🚩 Flag 5 – Initial Access via Pre-Staged AnyDesk](#-flag-5--initial-access-via-pre-staged-anydesk)
  - [🚩 Flag 6 – Command and Control via wsync.exe](#-flag-6--command-and-control-via-wsyncexe)
  - [🚩 Flag 7 – Reconnaissance via AdvancedIPScanner](#-flag-7--reconnaissance-via-advancedipscanner)
  - [🚩 Flag 8 – Lateral Movement via Stolen Credentials](#-flag-8--lateral-movement-via-stolen-credentials)
  - [🚩 Flag 9 – Tool Transfer via LOLBIN and PowerShell](#-flag-9--tool-transfer-via-lolbin-and-powershell)
  - [🚩 Flag 10 – Exfiltration via st.exe Archive](#-flag-10--exfiltration-via-stexe-archive)
  - [🚩 Flag 11 – Ransomware Deployment via updater.exe](#-flag-11--ransomware-deployment-via-updaterexe)
  - [🚩 Flag 12 – Anti-Forensics via clean.bat](#-flag-12--anti-forensics-via-cleanbat)
- [🌐 Network Indicators of Compromise](#-network-indicators-of-compromise)
- [🚨 Detection Gaps & Recommendations](#-detection-gaps--recommendations)
- [🧾 Final Assessment](#-final-assessment)
- [📎 Analyst Notes](#-analyst-notes)

---

## 🧠 Hunt Overview

This incident involved a returning threat actor using access pre-staged during a prior compromise (The Broker). No new initial compromise was required. The attacker reconnected via AnyDesk at 7:21 PM and executed a structured attack chain across approximately three hours.

The attack moved through six phases: tool deployment, defense evasion, credential theft, lateral movement, data exfiltration, and ransomware encryption. The attacker showed clear operational planning. Defender was disabled before any ransomware activity. Credentials were stolen and used to pivot to a server. Data was archived and staged for exfiltration before encryption started. The binary was cleaned up after encryption completed.

A key investigative challenge was the 47-day gap between the incident and the investigation. MDE Advanced Hunting retains logs for only 30 days. This was identified during the investigation. Azure Log Analytics retained the necessary telemetry and served as the sole platform for all queries.

---

## ⚔️ Attack Timeline

| Time (UTC) | Event |
|------------|-------|
| 12:00 PM | Attacker gains access via Guacamole RDP from 10.0.8.5 and 10.0.8.8 |
| 12:17 PM | scan.exe (AdvancedIPScanner) downloaded via bitsadmin from sync.cloud-endpoint.net |
| 12:22 PM | wsync.exe (C2 beacon v1) dropped to C:\ProgramData\ |
| 7:15 PM | AnyDesk activated from C:\Users\Public\ |
| 7:21 PM | Attacker reconnects via AnyDesk from 88.97.164.155 |
| 8:22 PM | wsync.exe beacon v1 deployed (C2 attempt fails) |
| 8:44 PM | wsync.exe beacon v2 deployed (replacement, different hash) |
| 8:50 PM | kill.bat downloaded via bitsadmin to disable Defender |
| 9:03 PM | DisableAntiSpyware set in registry via reg.exe |
| 9:05 PM | Shadow copies deleted via vssadmin |
| 9:11 PM | tasklist \| findstr lsass executed |
| 9:42 PM | \Device\NamedPipe\lsass accessed - credentials stolen |
| 10:15 PM | updater.exe staged on as-srv via powershell.exe |
| 10:16 PM | SMB enumeration of 10.1.0.154 and 10.1.0.183 |
| 10:18 PM | akira_readme.txt dropped - encryption begins |
| 10:20 PM | clean.bat runs - ransomware binary deleted |
| 10:24 PM | st.exe creates exfil_data.zip in C:\Users\Public\ |

---

## 🧬 MITRE ATT&CK Summary

| Flag | Technique | MITRE ID | Phase | Priority |
|-----:|-----------|----------|-------|----------|
| 1 | Modify Registry | T1112 | Defense Evasion | Critical |
| 2 | Impair Defenses | T1562 | Defense Evasion | Critical |
| 3 | Inhibit System Recovery | T1490 | Impact | Critical |
| 4 | OS Credential Dumping | T1003 | Credential Access | Critical |
| 5 | External Remote Services | T1133 | Initial Access | High |
| 6 | Remote Access Tools | T1219 | Command & Control | High |
| 7 | Network Share Discovery | T1135 | Discovery | Medium |
| 8 | Remote Services (SMB) | T1021 | Lateral Movement | High |
| 9 | Ingress Tool Transfer | T1105 | Command & Control | High |
| 10 | Archive Collected Data | T1560 | Collection | High |
| 11 | Data Encrypted for Impact | T1486 | Impact | Critical |
| 12 | Indicator Removal | T1070 | Defense Evasion | High |

---

## 🔍 Flag Analysis

---

<details>
<summary id="-flag-1--defense-evasion-via-registry-modification">🚩 <strong>Flag 1: Defense Evasion via Registry Modification</strong></summary>

### 🎯 Objective
Disable Windows Defender to allow ransomware execution without interference.

### 📌 Finding
The attacker used reg.exe to set DisableAntiSpyware to 1 at 21:03:42 UTC. This disabled Windows Defender before any ransomware activity occurred.

### 🔍 Evidence

| Field | Value |
|-------|-------|
| Host | as-pc2 |
| Timestamp | 2026-01-27 21:03:42 UTC |
| Process | reg.exe |
| Registry Key | HKLM\SOFTWARE\Policies\Microsoft\Windows Defender |
| Value Set | DisableAntiSpyware = 1 |

### 💡 Why it matters
Disabling Defender removed the primary endpoint protection before ransomware execution. This is a standard pre-encryption step and confirms the attacker understood the defensive environment. The timestamp of 21:03:42 UTC represents the earliest viable detection opportunity in this incident.

### 🔧 KQL Query Used
```kql
DeviceRegistryEvents
| where Timestamp between (datetime(2026-01-27T20:00:00Z) .. datetime(2026-01-27T23:59:00Z))
| where RegistryValueName == "DisableAntiSpyware"
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData
```

### 🛠️ Detection Recommendation

**Hunting Tip:**
Alert on any modification to Windows Defender registry keys. DisableAntiSpyware being set to 1 should be a high-priority alert in any SIEM. There is no legitimate reason for this to occur in most environments.

</details>

---

<details>
<summary id="-flag-2--defense-evasion-via-killbat">🚩 <strong>Flag 2: Defense Evasion via kill.bat</strong></summary>

### 🎯 Objective
Download and execute a script to suppress security tooling before ransomware deployment.

### 📌 Finding
kill.bat was downloaded via bitsadmin from sync.cloud-endpoint.net and executed to impair endpoint defenses. It was used in combination with the registry modification to fully disable Defender.

### 🔍 Evidence

| Field | Value |
|-------|-------|
| Host | as-pc2 |
| File | kill.bat |
| SHA256 | 0e7da57d92eaa6bda9d0bbc24b5f0827250aa42f295fd056ded50c6e3c3fb96c |
| Download Method | bitsadmin.exe |
| Source Domain | sync.cloud-endpoint.net |

### 💡 Why it matters
Using a LOLBIN to download a defense evasion script blends the activity with normal Windows behavior. bitsadmin is a legitimate tool, which makes this transfer harder to detect without behavioral rules tied to external domain usage.

### 🔧 KQL Query Used
```kql
DeviceProcessEvents
| where Timestamp between (datetime(2026-01-27T00:00:00Z) .. datetime(2026-01-27T23:59:00Z))
| where FileName == "bitsadmin.exe"
| project Timestamp, DeviceName, ProcessCommandLine
```

### 🛠️ Detection Recommendation

**Hunting Tip:**
Flag bitsadmin.exe usage that references external domains. Legitimate enterprise use of bitsadmin is rare. Any download to a user-writable directory from an external host should generate an alert.

</details>

---

<details>
<summary id="-flag-3--inhibit-system-recovery-via-shadow-copy-deletion">🚩 <strong>Flag 3: Inhibit System Recovery via Shadow Copy Deletion</strong></summary>

### 🎯 Objective
Remove Volume Shadow Copies to prevent file recovery after encryption.

### 📌 Finding
vssadmin delete shadows /all /quiet was executed at approximately 21:05 UTC. All VSS snapshots were removed before ransomware execution began.

### 🔍 Evidence

| Field | Value |
|-------|-------|
| Host | as-pc2 |
| Process | vssadmin.exe |
| Command | delete shadows /all /quiet |
| Timestamp | 2026-01-27 21:05 UTC |

### 💡 Why it matters
Without shadow copies, victims cannot restore files from local backups. This is a near-universal ransomware pre-encryption step. Its presence confirms ransomware deployment was planned and imminent at this point in the timeline.

### 🔧 KQL Query Used
```kql
DeviceProcessEvents
| where ProcessCommandLine has "vssadmin" and ProcessCommandLine has "delete shadows"
| project Timestamp, DeviceName, ProcessCommandLine
```

### 🛠️ Detection Recommendation

**Hunting Tip:**
Alert immediately on any vssadmin delete shadows command. There is no legitimate business reason to run this in most environments. Treat it as a critical-priority indicator.

</details>

---

<details>
<summary id="-flag-4--credential-access-via-lsass-named-pipe">🚩 <strong>Flag 4: Credential Access via LSASS Named Pipe</strong></summary>

### 🎯 Objective
Steal credentials from LSASS to enable lateral movement to privileged systems.

### 📌 Finding
The attacker ran tasklist | findstr lsass at 21:11 UTC to confirm the LSASS process was running. At 21:42 UTC, the named pipe \Device\NamedPipe\lsass was accessed, indicating credential extraction.

### 🔍 Evidence

| Field | Value |
|-------|-------|
| Host | as-pc2 |
| Precursor Command | tasklist \| findstr lsass |
| Named Pipe Accessed | \Device\NamedPipe\lsass |
| Timestamp | 2026-01-27 21:42 UTC |
| ActionType | NamedPipeEvent |

### 💡 Why it matters
The stolen credentials were used minutes later to authenticate to AS-SRV as as.srv.administrator. Without this step, lateral movement to the server would not have been possible. The named pipe access was the critical link between credential theft and domain compromise.

### 🔧 KQL Query Used
```kql
DeviceEvents
| where Timestamp between (datetime(2026-01-27T20:00:00Z) .. datetime(2026-01-27T23:59:00Z))
| where DeviceName == "as-pc2"
| where ActionType == "NamedPipeEvent"
| extend PipeName = tostring(AdditionalFields.PipeName)
| where PipeName has "lsass"
| project Timestamp, InitiatingProcessFileName, PipeName
| order by Timestamp asc
```

### 🛠️ Detection Recommendation

**Hunting Tip:**
Search for named pipe events where the pipe is named lsass, not just processes connecting to lsass. Combine with preceding tasklist or findstr commands targeting lsass to build a high-confidence detection sequence.

</details>

---

<details>
<summary id="-flag-5--initial-access-via-pre-staged-anydesk">🚩 <strong>Flag 5: Initial Access via Pre-Staged AnyDesk</strong></summary>

### 🎯 Objective
Re-establish persistent remote access using a backdoor placed during the prior compromise.

### 📌 Finding
AnyDesk was pre-staged in C:\Users\Public\ and activated at 7:15 PM. The attacker connected from external IP 88.97.164.155 via relay-0b975d23.net.anydesk.com at 7:21 PM.

### 🔍 Evidence

| Field | Value |
|-------|-------|
| Host | as-pc2 |
| Tool | AnyDesk |
| Directory | C:\Users\Public\ |
| Attacker IP | 88.97.164.155 |
| Relay Domain | relay-0b975d23.net.anydesk.com |
| Connection Time | 2026-01-27 19:21 UTC |

### 💡 Why it matters
Pre-staged remote access tools represent a critical persistence risk. The attacker did not need to re-compromise the environment. Existing access allowed an immediate return 47 days later with no new exploit required.

### 🔧 KQL Query Used
```kql
DeviceNetworkEvents
| where RemoteUrl has "anydesk.com"
| project Timestamp, DeviceName, RemoteIP, RemoteUrl, InitiatingProcessFileName
```

### 🛠️ Detection Recommendation

**Hunting Tip:**
Hunt for AnyDesk and similar remote access tools running from non-standard directories such as C:\Users\Public\. Flag any remote access tool not present in the approved software inventory. Post-incident, audit all running processes for unapproved remote tools.

</details>

---

<details>
<summary id="-flag-6--command-and-control-via-wsyncexe">🚩 <strong>Flag 6: Command and Control via wsync.exe</strong></summary>

### 🎯 Objective
Establish a persistent C2 channel to receive commands and support exfiltration.

### 📌 Finding
wsync.exe was deployed to C:\ProgramData\. The first beacon failed and was replaced with a new binary with a different SHA256. Both versions communicated with the same C2 infrastructure proxied through Cloudflare.

### 🔍 Evidence

| Field | Value |
|-------|-------|
| Host | as-pc2 |
| File | wsync.exe |
| Directory | C:\ProgramData\ |
| C2 IPs | 104.21.30.237, 172.67.174.46 |
| Beacon v1 SHA256 | 66b876c52946f4aed47dd696d790972ff265b6f4451dab54245bc4ef1206d90b |
| Beacon v2 SHA256 | 0072ca0d0adc9a1b2e1625db4409f57fc32b5a09c414786bf08c4d8e6a073654 |

### 💡 Why it matters
Two beacons with the same filename but different hashes confirm the attacker replaced a failing tool mid-operation. This behavior is detectable when hash-based alerting is combined with file creation events in sensitive directories.

### 🔧 KQL Query Used
```kql
DeviceFileEvents
| where FileName == "wsync.exe"
| project Timestamp, DeviceName, SHA256, FolderPath, ActionType
```

### 🛠️ Detection Recommendation

**Hunting Tip:**
Alert on new executables appearing in C:\ProgramData\ from unexpected parent processes. Flag outbound connections to known Cloudflare proxy IPs from non-browser processes. Two files with the same name and different hashes in a short window indicate tool replacement.

</details>

---

<details>
<summary id="-flag-7--reconnaissance-via-advancedipscanner">🚩 <strong>Flag 7: Reconnaissance via AdvancedIPScanner</strong></summary>

### 🎯 Objective
Enumerate internal network hosts to identify targets for lateral movement.

### 📌 Finding
scan.exe, a renamed copy of AdvancedIPScanner, was dropped and executed with portable mode arguments. It identified two internal targets at 10.1.0.154 and 10.1.0.183.

### 🔍 Evidence

| Field | Value |
|-------|-------|
| Host | as-pc2 |
| File | scan.exe |
| SHA256 | 26d5748ffe6bd95e3fee6ce184d388a1a681006dc23a0f08d53c083c593c193b |
| Arguments | /portable "C:/Users/david.mitchell/Downloads/" /lng en_us |
| Targets Found | 10.1.0.154, 10.1.0.183 |

### 💡 Why it matters
Renaming known tools is a common masquerading technique. The /portable flag writes scan results locally and avoids registry traces, reducing the forensic footprint of the reconnaissance activity.

### 🔧 KQL Query Used
```kql
DeviceProcessEvents
| where ProcessCommandLine has "/portable" and ProcessCommandLine has "/lng"
| project Timestamp, DeviceName, FileName, ProcessCommandLine
```

### 🛠️ Detection Recommendation

**Hunting Tip:**
Hunt for AdvancedIPScanner by its command-line arguments rather than filename. The /portable flag is a reliable indicator regardless of what the binary is named.

</details>

---

<details>
<summary id="-flag-8--lateral-movement-via-stolen-credentials">🚩 <strong>Flag 8: Lateral Movement via Stolen Credentials</strong></summary>

### 🎯 Objective
Authenticate to a privileged server using credentials stolen from LSASS.

### 📌 Finding
The account as.srv.administrator was used to authenticate to AS-SRV from 10.0.8.9 via network and remote interactive logon. This followed directly from the LSASS credential dump on AS-PC2.

### 🔍 Evidence

| Field | Value |
|-------|-------|
| Source Host | as-pc2 |
| Target Host | as-srv |
| Account Used | as.srv.administrator |
| Source IP | 10.0.8.9 |
| Logon Type | Network and Remote Interactive |

### 💡 Why it matters
A server administrator account authenticating from a workstation is a strong lateral movement signal. This pivot gave the attacker access to AS-SRV, where the ransomware was ultimately staged and executed.

### 🔧 KQL Query Used
```kql
DeviceLogonEvents
| where DeviceName == "as-srv"
| where AccountName == "as.srv.administrator"
| project Timestamp, DeviceName, AccountName, RemoteIP, LogonType
```

### 🛠️ Detection Recommendation

**Hunting Tip:**
Alert on privileged account logons originating from workstations. Implement Privileged Access Workstations to restrict where administrator credentials can authenticate from.

</details>

---

<details>
<summary id="-flag-9--tool-transfer-via-lolbin-and-powershell">🚩 <strong>Flag 9: Tool Transfer via LOLBIN and PowerShell</strong></summary>

### 🎯 Objective
Download attacker tools to victim hosts using built-in Windows utilities.

### 📌 Finding
bitsadmin.exe was the primary download method. When it was insufficient, Invoke-WebRequest was used as a fallback. Both methods pulled tools from sync.cloud-endpoint.net and cdn.cloud-endpoint.net.

### 🔍 Evidence

| Field | Value |
|-------|-------|
| Primary LOLBIN | bitsadmin.exe |
| Fallback Method | Invoke-WebRequest (PowerShell) |
| Delivery Domain 1 | sync.cloud-endpoint.net |
| Delivery Domain 2 | cdn.cloud-endpoint.net |

### 💡 Why it matters
Using multiple native download methods shows preparation and adaptability. Both bitsadmin and PowerShell web requests are built into Windows, which reduces detection likelihood without specific behavioral rules in place.

### 🔧 KQL Query Used
```kql
DeviceProcessEvents
| where ProcessCommandLine has "bitsadmin" or ProcessCommandLine has "Invoke-WebRequest"
| where ProcessCommandLine has "http"
| project Timestamp, DeviceName, ProcessCommandLine
```

### 🛠️ Detection Recommendation

**Hunting Tip:**
Baseline normal usage of bitsadmin and PowerShell web requests in your environment. Any external download to a user-writable directory should generate an alert, regardless of which tool performed it.

</details>

---

<details>
<summary id="-flag-10--exfiltration-via-stexe-archive">🚩 <strong>Flag 10: Exfiltration via st.exe Archive</strong></summary>

### 🎯 Objective
Compress and stage sensitive data for exfiltration before encrypting the environment.

### 📌 Finding
st.exe created exfil_data.zip in C:\Users\Public\ at 22:24 UTC. The archive was staged before encryption and likely transferred via the active C2 channel.

### 🔍 Evidence

| Field | Value |
|-------|-------|
| Host | as-pc2 |
| Tool | st.exe |
| SHA256 | 512a1f4ed9f512572608c729a2b89f44ea66a40433073aedcd914bd2d33b7015 |
| Archive Created | exfil_data.zip |
| Staging Directory | C:\Users\Public\ |

### 💡 Why it matters
Exfiltration before encryption is a defining characteristic of double extortion ransomware. Akira threatens to publish stolen data if the ransom is not paid. This makes exfiltration a separate and serious impact beyond the encryption itself.

### 🔧 KQL Query Used
```kql
DeviceFileEvents
| where FileName has ".zip" and FolderPath has "Public"
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessFileName
```

### 🛠️ Detection Recommendation

**Hunting Tip:**
Alert on large archive files created in C:\Users\Public\ by non-standard processes. DLP controls should flag large data transfers over established C2 channels, particularly to Cloudflare-proxied infrastructure.

</details>

---

<details>
<summary id="-flag-11--ransomware-deployment-via-updaterexe">🚩 <strong>Flag 11: Ransomware Deployment via updater.exe</strong></summary>

### 🎯 Objective
Execute the Akira ransomware payload to encrypt victim files and drop a ransom note.

### 📌 Finding
updater.exe was staged on AS-SRV by powershell.exe from cdn.cloud-endpoint.net at 22:15 UTC. It dropped akira_readme.txt at 22:18:33 UTC, marking the start of encryption. All encrypted files received the .akira extension.

### 🔍 Evidence

| Field | Value |
|-------|-------|
| Host | as-srv |
| Ransomware File | updater.exe |
| SHA256 | e609d070ee9f76934d73353be4ef7ff34b3ecc3a2d1e5d052140ed4cb9e4752b |
| Staging Process | powershell.exe |
| Ransom Note | akira_readme.txt |
| Encryption Start | 2026-01-27 22:18:33 UTC |
| File Extension | .akira |
| Ransom Group | Akira |
| TOR Address | akiral2iz6a7qgd3ayp3l6yub7xx2uep76idk3u2kollpj5z3z636bad.onion |
| Victim ID | 813R-QWJM-XKIJ |

### 💡 Why it matters
The ransomware was disguised as a Windows Update process to avoid suspicion. Encryption began less than three minutes after staging. The ransom note confirms the Akira group and provides the victim ID needed for negotiation.

### 🔧 KQL Query Used
```kql
DeviceFileEvents
| where FileName has "akira_readme"
| summarize count() by DeviceName
| order by count_ desc
```

### 🛠️ Detection Recommendation

**Hunting Tip:**
Monitor for ransom note creation by filename pattern. Alert on powershell.exe creating executables in writable directories when the source is an external URL. Searching for the ransom note drop is more reliable for scoping than searching for the ransomware binary, which may be deleted.

</details>

---

<details>
<summary id="-flag-12--anti-forensics-via-cleanbat">🚩 <strong>Flag 12: Anti-Forensics via clean.bat</strong></summary>

### 🎯 Objective
Delete the ransomware binary after encryption to hinder forensic recovery and malware analysis.

### 📌 Finding
clean.bat executed approximately two minutes after ransomware deployment and deleted updater.exe from AS-SRV. This removed the primary malware artifact from the compromised host.

### 🔍 Evidence

| Field | Value |
|-------|-------|
| Host | as-srv |
| File | clean.bat |
| Purpose | Delete updater.exe post-encryption |
| Execution Time | Approximately 22:20 UTC |

### 💡 Why it matters
Deleting the ransomware binary after execution complicates malware analysis and slows attribution. Without the binary, defenders lose the ability to analyze encryption methods or identify decryption opportunities without paying the ransom.

### 🔧 KQL Query Used
```kql
DeviceFileEvents
| where FileName == "clean.bat"
    or (ActionType == "FileDeleted" and FileName == "updater.exe")
| project Timestamp, DeviceName, FileName, ActionType
```

### 🛠️ Detection Recommendation

**Hunting Tip:**
Retain endpoint telemetry beyond process execution. Even when a binary is deleted, process creation logs, network connections, and file modification events remain and support full reconstruction of the attack chain.

</details>

---

## 🌐 Network Indicators of Compromise

| Indicator | Type | Role |
|-----------|------|------|
| sync.cloud-endpoint.net | Domain | Initial tool delivery |
| cdn.cloud-endpoint.net | Domain | Ransomware staging |
| 104.21.30.237 | IP Address | C2 server (Cloudflare proxied) |
| 172.67.174.46 | IP Address | C2 server (Cloudflare proxied) |
| relay-0b975d23.net.anydesk.com | Domain | AnyDesk persistent backdoor relay |
| 88.97.164.155 | IP Address | Attacker external IP |
| 10.1.0.154 | Internal IP | SMB share enumeration target |
| 10.1.0.183 | Internal IP | SMB share enumeration target |

---

## 🚨 Detection Gaps & Recommendations

### Observed Gaps
- MDE Advanced Hunting log retention (30 days) was insufficient for a 47-day-old incident. Azure Log Analytics retained the necessary telemetry, but this was not known at investigation start.
- Pre-staged AnyDesk was not detected or removed after the initial compromise. This enabled a seamless return with no new intrusion required.
- bitsadmin downloading attacker tools from external domains generated no alerts.
- Registry modification disabling Windows Defender fired no alert despite occurring 75 minutes before encryption.
- Shadow copy deletion went undetected until post-incident review.

### Recommendations
- Extend log retention beyond 30 days for all critical endpoint telemetry. A minimum of 90 days is recommended.
- Implement a post-incident remediation checklist that includes auditing all installed remote access tools and non-standard executables in user-writable directories.
- Create detection rules for bitsadmin and Invoke-WebRequest downloading from external domains to user-writable paths.
- Alert immediately on any modification to Windows Defender registry keys. Treat as critical priority.
- Alert on vssadmin delete shadows. This command has no legitimate use in most environments.
- Deploy a Privileged Access Workstation model to restrict where administrator accounts can authenticate from.

---

## 🧾 Final Assessment

This attack was a well-structured double extortion ransomware operation. The attacker demonstrated clear planning across every phase: using pre-staged access to avoid re-compromise, replacing a failing C2 beacon mid-operation, exfiltrating data before encrypting, and deleting the ransomware binary to slow forensic response.

The real detection opportunity was not the ransom note. It was the DisableAntiSpyware registry modification at 21:03:42 UTC. An alert at that moment would have given defenders approximately 75 minutes to respond before encryption began.

No effective alerting stopped the attacker at any stage. The use of legitimate tools such as bitsadmin, AnyDesk, reg.exe, and vssadmin allowed the operation to blend with normal system activity. Behavioral detection rules tied to specific command-line patterns and activity context would have provided multiple intervention points throughout the attack chain.

All 40 investigation questions were answered. The complete attack chain was reconstructed from initial access through anti-forensics using only Azure Log Analytics telemetry retained in the LAW-Cyber-Range workspace.

---

## 📎 Analyst Notes

- The investigation was conducted 47 days post-incident. MDE had no data. All findings came from Azure Log Analytics.
- The hardest question was Q14 (named pipe access). The breakthrough came from shifting the search angle from processes connecting to lsass to pipes named lsass.
- Q6 (cdn.cloud-endpoint.net) only appeared in DeviceNetworkEvents on AS-SRV. A broad cross-table search across all devices was required to surface it.
- Two wsync.exe files with the same name but different SHA256 hashes confirmed the C2 beacon was swapped mid-operation.
- Host scope was confirmed by searching for ransom note drops, not just ransomware binary presence. One host had the binary but was not confirmed compromised.
- Techniques are mapped directly to MITRE ATT&CK. All evidence is reproducible via the KQL queries documented in each flag section.
- Report structured for portfolio and interview review.
- Platform: SancLogic Cyber Range | sanclogic.com

---
