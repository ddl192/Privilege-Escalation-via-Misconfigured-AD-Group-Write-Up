
---

# Detection of Privilege Escalation via Active Directory Misconfigurations

---

## 1) Environment & AD Structure Overview

**Domain Information**

* Domain: CORP.LOCAL
* Forest Level: Windows Server 2019 (single-forest, single-domain)

**Core Infrastructure**

* **Domain Controller:** DC01
* OS: Windows Server 2019 Datacenter
* Roles: AD DS, DNS
* Purpose: Central authentication, Kerberos ticket issuance, group/GPO management

**Workstations**

* **WS-USER (DESKTOP-SKCGSH6)**

  * OS: Windows 10 Pro
  * Domain-joined
  * Represents a typical end-user endpoint

**SIEM & Telemetry Stack**

* Elastic Stack v9.2.3 deployed on Ubuntu Linux (Docker-based)
* Components: Elasticsearch, Logstash, Fleet Server (Elastic Agent management)

**Elastic Agent Deployment**

* Domain Controller (DC01)
* Windows Pro workstation #1
* Collected logs: Windows Security, System, Application + Sysmon v15.15 (SOC-hardened SwiftOnSecurity configuration)

**Key Telemetry & Coverage**

* **Security logs:** 4624, 4672, 4732, 5136, 5140
* **Sysmon:** 1 (Process Creation), 3 (Network Connection), 8 (CreateRemoteThread) 11 (File Creation)
* Provides full visibility of credential use, process activity, inter-process actions, network connections, and object modifications.

![image](https://github.com/user-attachments/assets/eacc86d8-88f1-49e0-b1b2-fe9bb79b2f8d)

---

## 2) Observed Activity & Detection

### Initial Privilege Escalation

**Context:**
Using Kali Linux and BloodHound, the AD architecture, group memberships, and delegated permissions were analyzed. Critical misconfigurations were identified that allowed standard domain users to escalate privileges:

* **Unconstrained Delegation** on DC01
* **Built-in Administrator account** with `PasswordNeverExpires` in multiple Tier-0 groups
* **Delegated ACEs** granting **GenericAll** and **AddKeyCredentialLink** on key computer objects (e.g., [RR1@CORP.LOCAL](mailto:RR1@CORP.LOCAL))

These misconfigurations enable privilege escalation without exploiting vulnerabilities - using legitimate AD operations.

**Execution Observed:**

* User **rr1** added to a privileged group (Account Operators) via DC
* Powershell.exe executed on WS-USER (DESKTOP-SKCGSH6) with the new privileges
* Telegram bot triggered **critical alert** outside normal business hours

**Alert Details:**

<img width="1555" height="1022" alt="123123" src="https://github.com/user-attachments/assets/8dc3461f-4be8-4f1f-ad87-9e9e8e6bef98" />


* **Time:** 2026-03-13 17:27:31 UTC
* **User:** rr1
* **Host:** desktop-skcgsh6
* **Severity:** Critical
* **MITRE ATT&CK Mapping:** TA0003 → TA0004 → TA0002
* **Chain:** 4732 → 4672 → 4688
* **Observation:** Off-hours execution increases anomaly confidence

---

### Authentication & Activity Evidence

**Domain Controller (DC01) - Kerberos Events:**

* **4768** - TGT request for rr1
* **4769** - Service ticket request (CIFS)

**Workstation Evidence (DESKTOP-SKCGSH6) - Windows Security + Sysmon:**

* **4732** - User added to security-enabled local group
  ![4732 Event](https://github.com/user-attachments/assets/4c8f9531-6a9e-4cd4-9e36-98a264e66311)

* **4672** - Special privileges assigned at logon
  ![4672 Event](https://github.com/user-attachments/assets/12a61bbd-074b-4f5d-8bb1-ea4004a4c436)

* **4688** - Process creation: `powershell.exe`
  ![4688 Event](https://github.com/user-attachments/assets/2823e9e9-1d99-430d-82a5-8295f03e9b70)

**Process Observations:**

* Only `powershell.exe` launched during escalation chain
* No additional tools (cmd.exe, wmic.exe, net.exe) used
* Commands executed were standard administrative tasks; no exploit/malware detected

---

## 3) AD Misconfigurations

**Critical Points Identified Using Kali Linux + BloodHound:**

<img width="1920" height="974" alt="AD Detection Engineering - Google Chrome 10 02 2026 15_57_07" src="https://github.com/user-attachments/assets/2ab2a5c1-e9df-4e62-966f-867a91db496f" />


| Misconfiguration                                          | Impact / Risk                                                           |
| --------------------------------------------------------- | ----------------------------------------------------------------------- |
| Unconstrained Delegation (DC01)                           | Allows Kerberos TGT capture & abuse                                     |
| Built-in Administrator, PasswordNeverExpires              | Single point of compromise in multiple Tier-0 groups                    |
| Delegated ACEs on [RR1@CORP.LOCAL](mailto:RR1@CORP.LOCAL) | GenericAll, AddKeyCredentialLink → Shadow Credentials & RBCD abuse      |
| Nested privileged groups                                  | Junior admin compromise cascades to full control over sensitive objects |
| GPO control paths                                         | Potential domain-wide execution via GPO modification                    |

These findings validate the ability for a non-privileged user to escalate to Tier-1 / Tier-0 privileges entirely through misconfigurations.

![BloodHound Graph](https://github.com/user-attachments/assets/0cc979df-9d3f-439c-a5a3-dc14e4b4f265)

---

## 4) Detection Logic & Correlation Strategy

**Objective:**
Identify abnormal privilege escalation behavior, off-hours activity, and suspicious process execution leveraging legitimate credentials.

<img width="1865" height="821" alt="vm mshome net - VMware ESXi - Google Chrome 13 03 2026 20_57_08" src="https://github.com/user-attachments/assets/6436471a-347a-4f83-b4b5-e2e8b0016f68" />

**Behavioral Detection Logic:**

* Detect a **three-step attack chain** via Kibana EQL:

  **4732** - user added to privileged group (occurs on DC)
  **4672** - user logged in and received special privileges
  **4688** - suspicious process launched (`powershell.exe`, `cmd.exe`, etc.)

* Each event individually is normal; **all three sequentially for the same user → alert**

**Initial Sequence Rule (caused false positives):**

<img width="958" height="677" alt="vm mshome net - VMware ESXi - Google Chrome 11 03 2026 12_31_19" src="https://github.com/user-attachments/assets/773deb73-13f6-4c5b-9c5a-ea0690e3b239" />


```kql
sequence by user.name, host.name with maxspan=10m
  [any where event.code == "4672"]
  [any where event.code == "4688" and
     process.name in (
       "cmd.exe","powershell.exe","powershell_ise.exe",
       "net.exe","net1.exe","wmic.exe","sc.exe",
       "schtasks.exe","at.exe","psexec.exe",
       "reg.exe","regsvr32.exe"
     )
  ]
```

**Refined Sequence Rule:**

<img width="859" height="763" alt="vm mshome net - VMware ESXi - Google Chrome 13 03 2026 20_58_00" src="https://github.com/user-attachments/assets/a5e1681f-716e-4287-b1c6-bd20b52133da" />


```kql
sequence with maxspan=30m
  [any where event.code == "4732" and user.target.name in ("User1")]
  [any where event.code == "4672" and user.name == "rr1"]
  [any where event.code == "4688" and user.name == "rr1"
     and process.name in (
       "cmd.exe","powershell.exe","powershell_ise.exe",
       "net.exe","net1.exe","wmic.exe","sc.exe",
       "schtasks.exe","psexec.exe","reg.exe"
     )
  ]
```


## Timeline Tool for Testing Correlation Rules

The **Timeline** tool was used to test and refine detection rules before deployment. It allows analysts to:

* Simulate sequences of events (4732 → 4672 → 4688)
* Check that user, host, group, and process fields are correctly captured
* Identify normal system activity and reduce false positives
* Verify alert timing and correlation across hosts

**Benefit:** Ensures rules work as intended in Elastic SIEM without triggering unnecessary alerts.

<img width="1867" height="686" alt="vm mshome net - VMware ESXi - Google Chrome 13 03 2026 21_01_40" src="https://github.com/user-attachments/assets/f484b910-0658-4a01-990e-24bc8baf777f" />


---


**Telegram Bot Workflow:**

* Windows logs → Elastic Agent → Elasticsearch
* Kibana EQL sequence triggers → Webhook → alerts-logon-events index
* Python/PowerShell script polls the index every 20s:

  Queries new alert documents
  Determines alert type (sequence vs normal)
  Enriches missing fields (user, host, process) and sends to Telegram

**Field Extraction Logic:**

| Field   | Source Event                    | Notes                                           |
| ------- | ------------------------------- | ----------------------------------------------- |
| group   | 4732 (on DC)                    | Group being escalated                           |
| user    | 4672 (first non-system account) | Skip SYSTEM, machine accounts, session accounts |
| host    | 4688                            | Process host                                    |
| process | 4688                            | Process executed                                |

**Key Fixes Implemented:**

* Filtered machine accounts (`$`) and session accounts (`dwm-*`, `umfd-*`)
* Extract host/process strictly from 4688 event
* Extract group from 4732, user from 4672

---

## 5) Analyst Assessment

**Key Observations:**

* Privilege escalation achieved entirely via AD misconfigurations
* Off-hours execution of administrative process increased anomaly confidence
* Elastic SIEM reliably correlates Security + Sysmon + AD telemetry
* Behavioral monitoring and sequence-based detection successfully raised high-confidence alerts

This demonstrates that **behavioral analysis**, combined with proper AD audit coverage, can detect post-compromise privilege abuse even without external tools or malware.

---

## 6) Recommendations & Risk Mitigation

1. **Strengthen Credential Security**

   * Enforce MFA for all domain accounts
   * Audit and rotate privileged credentials
   * Implement least-privilege model

2. **Mitigate Misconfigurations**

   * Review and restrict delegated ACEs (GenericAll, AddKeyCredentialLink)
   * Secure Unconstrained Delegation accounts or disable where unnecessary
   * Harden built-in Administrator accounts

3. **Enhance Detection & Logging**

   * Expand Sysmon coverage: inter-process/thread injection (Event IDs 8,10)
   * Correlate Security + Sysmon + AD logs in SIEM
   * Monitor off-hours privilege changes and process execution

4. **Operational & Preventive Measures**

   * Use BloodHound / ADACLScanner to regularly audit AD structure and permissions
   * Implement context-aware dashboards for critical group modifications
   * Conduct simulated phishing and privilege abuse drills to test detection

---

## 7) Summary

* AD misconfigurations can lead to privilege escalation without exploits
* Security + Sysmon logs fully capture user actions, providing actionable telemetry
* Behavioral analysis and off-hours correlation improve SOC detection confidence
* Elastic SIEM with alert automation (Telegram bot) ensures real-time response
* Mitigation requires both configuration hardening and continuous monitoring

This environment validates a **defensible SOC detection use case** for identity-based privilege escalation via misconfigured AD objects and delegated permissions.

---

