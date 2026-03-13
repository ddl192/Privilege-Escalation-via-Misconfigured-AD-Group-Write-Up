
---

# Detection of Privilege Escalation via Active Directory Misconfigurations

**Write-up**

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
* **Sysmon:** 1 (Process Creation), 3 (Network Connection), 8 (CreateRemoteThread), 11 (File Creation)
* Provides full visibility of credential use, process activity, inter-process actions, network connections, and object modifications.

---

## 2) Observed Activity & Detection

### Initial Privilege Escalation

**Context:**
Using BloodHound and Kali Linux, the AD architecture, group memberships, and delegated permissions were analyzed. Critical misconfigurations were identified that allowed standard domain users to escalate privileges:

* **Unconstrained Delegation** on DC01
* **Built-in Administrator account** with `PasswordNeverExpires` in multiple Tier-0 groups
* **Delegated ACEs** granting **GenericAll** and **AddKeyCredentialLink** on key computer objects (e.g., [RR1@CORP.LOCAL](mailto:RR1@CORP.LOCAL))

These misconfigurations enable privilege escalation without exploiting vulnerabilities - using legitimate AD operations.

**Execution Observed:**

* User **rr1** added to a privileged group (Account Operators) via DC
* Powershell.exe executed on WS-USER (DESKTOP-SKCGSH6) with the new privileges
* Telegram bot triggered **critical alert** outside normal business hours

**Alert Details:**

* **Time:** 2026-03-13 17:27:31 UTC
* **User:** rr1
* **Host:** desktop-skcgsh6
* **Severity:** Critical
* **MITRE ATT&CK Mapping:** TA0003 → TA0004 → TA0002
* **Chain:** 4732 (User added to privileged group) → 4672 (Special privileges assigned) → 4688 (Suspicious process launched)
* **Observation:** Off-hours execution increases anomaly confidence

---

### Authentication & Activity Evidence

**Domain Controller (DC01) - Kerberos Events:**

* **4768** - TGT request for rr1
* **4769** - Service ticket request (CIFS)

**Workstation Evidence (DESKTOP-SKCGSH6) - Windows Security + Sysmon:**

* **4624** - Network logon (LogonType 3)
* **4672** - Special privileges assigned at logon
* **4688** - Process creation: `powershell.exe`
* **Sysmon 1,3,8,11** - Process creation, network connections, CreateRemoteThread, Process Access, File Creation
* Confirms activity with elevated privileges and administrative context

**Process Observations:**

* Only `powershell.exe` launched during escalation chain
* No additional tools (cmd.exe, wmic.exe, net.exe) used
* Commands executed were standard administrative tasks; no exploit/malware detected

---

## 3) AD Misconfigurations

**Critical Points Identified Using Kali Linux + BloodHound:**

| Misconfiguration                                          | Impact / Risk                                                           |
| --------------------------------------------------------- | ----------------------------------------------------------------------- |
| Unconstrained Delegation (DC01)                           | Allows Kerberos TGT capture & abuse                                     |
| Built-in Administrator, PasswordNeverExpires              | Single point of compromise in multiple Tier-0 groups                    |
| Delegated ACEs on [RR1@CORP.LOCAL](mailto:RR1@CORP.LOCAL) | GenericAll, AddKeyCredentialLink → Shadow Credentials & RBCD abuse      |
| Nested privileged groups                                  | Junior admin compromise cascades to full control over sensitive objects |
| GPO control paths                                         | Potential domain-wide execution via GPO modification                    |

These findings validate the ability for a non-privileged user to escalate to Tier-1 / Tier-0 privileges entirely through misconfigurations.

---

## 4) Detection Logic & Correlation Strategy

**Objective:**
Identify abnormal privilege escalation behavior, off-hours activity, and suspicious process execution leveraging legitimate credentials.

**Primary Signals:**

1. **Group Membership Change:** 4728 / 4732
2. **Privilege Assignment:** 4672
3. **Suspicious Process Launch:** 4688 with administrative tools (`powershell.exe`)

**Secondary Signals:**

* Off-hours activity (outside standard business hours)
* Unusual process patterns captured in Sysmon (network threads, inter-process access)
* AD/GPO modifications (5136) and admin share access (5140)

**Correlation:**

* Combine Security + Sysmon + AD logs for end-to-end traceability
* Alerts forwarded to Telegram bot → immediate SOC notification

---

## 5) Analyst Assessment

**Key Observations:**

* Privilege escalation achieved entirely via AD misconfigurations
* No exploits or malware required; legitimate operations triggered alerts
* Off-hours process execution provides high-confidence anomaly detection
* Elastic SIEM pipeline reliably correlates Security + Sysmon + AD telemetry

This demonstrates that **behavioral monitoring**, combined with proper AD audit coverage, can detect post-compromise privilege abuse even without external tools or malware.

---

## 6) Recommendations & Risk Mitigation

1. **Strengthen Credential Security**

   * Enforce MFA for all domain accounts, especially administrative
   * Audit and rotate privileged credentials regularly
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

This lab demonstrates that:

* AD misconfigurations can lead to privilege escalation without exploits
* Security + Sysmon logs fully capture user actions, providing actionable telemetry
* Behavioral analysis and off-hours correlation improve SOC detection confidence
* Elastic SIEM with alert automation (Telegram bot) ensures real-time response
* Mitigation requires both configuration hardening and continuous monitoring

The environment validates a **defensible SOC detection use case** for identity-based privilege escalation via misconfigured AD objects and delegated permissions.

---

Если хочешь, я могу ещё **добавить в отчёт наглядную схему цепочки 4732 → 4672 → 4688 с misconfigurations**, как диаграмму, чтобы выглядело как полный лабораторный отчёт для SOC.

Хочешь, чтобы я это сделал?
