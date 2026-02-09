
---

# Active Directory Detection Engineering Lab

**Phase 1 — Environment Setup, Visibility & Attack Surface Mapping**

---

## 1) Lab Objective

The goal of this home lab is to build a **realistic Active Directory detection environment** focused on:

* Identity-based attacks
* Privilege misuse
* Lateral movement using valid credentials
* Behavioral detection rather than exploit or malware signatures

At the current stage, the lab focuses on **visibility, logging correctness, and attack path discovery**, rather than active exploitation.

This approach reflects real-world SOC conditions, where detection quality depends primarily on telemetry completeness and correct correlation.

---

## 2) Environment & Infrastructure Overview

### Active Directory Environment

* **Domain:** `CORP.LOCAL`
* **Forest:** Single forest, single domain
* **Functional Level:** Windows Server (default)
* **Domain Controller:** `DC01`

**DC01**

* OS: Windows Server 2019 Datacenter
* Roles:

  * Active Directory Domain Services (AD DS)
  * DNS
* Purpose:

  * Central authentication authority
  * Group membership and GPO management
  * Kerberos ticket issuance
* Logging:

  * Windows Security Log
  * Directory Service Changes
  * Account Management
  * Kerberos Authentication & Service Tickets

---

### Workstations

**WS-USER (DESKTOP-SKCGSH6)**

* OS: Windows 10 Pro
* Domain-joined
* Represents a standard user endpoint

Purpose in the lab:

* Acts as a source or target for lateral movement
* Generates realistic workstation authentication and SMB telemetry
* Used to validate admin share access detection

---

### SIEM & Telemetry Stack

**Elastic Stack (v9.2.3)**

* Deployment: Ubuntu Linux (Docker-based)
* Components:

  * Elasticsearch
  * Fleet Server
  * Elastic Agent

**Elastic Agent**

* Deployed on:

  * DC01
  * Windows workstations
* Managed centrally via Fleet
* Responsible for:

  * Windows Security log collection
  * System & Application logs
  * Structured ECS parsing

**Log Sources Confirmed**

* `system.security`
* `system.system`
* `system.application`

---

### Sysmon

* Version: 15.15
* Configuration: SwiftOnSecurity (SOC-hardened baseline)
* Installed on:

  * DC01
  * Windows workstations

Coverage includes:

* Process creation
* Network connections
* Process access
* File creation
* Inter-process activity

---

## 3) Logging & Audit Policy Validation

A key requirement for detection engineering is **verifying that events are actually generated before writing detections**.

### Audit Policy Verification

Audit policies were reviewed and validated using:

```cmd
auditpol /get /category:*
```

Key subcategories enabled and confirmed:

* **Security Group Management**

  * Required for:

    * Event ID 4728 (member added to security-enabled global group)
    * Event ID 4732 (member added to domain local group)

* **Directory Service Changes**

  * Required for:

    * Event ID 5136 (GPO and AD object modification)

* **Logon / Logoff**

  * Required for:

    * Event ID 4624 (successful logon)
    * Event ID 4672 (special privileges assigned)

* **File Share**

  * Explicitly enabled to generate:

    * Event ID 5140 (network share access)

Audit policy for file share access was validated locally on the workstation, and successful `5140` events were confirmed both locally and in Elastic.

---

## 4) Confirmed Telemetry & Event Evidence

The following critical security events have been **successfully generated, collected, and indexed** in Elastic:

### Identity & Authentication

* **4624** — Successful logon (LogonType 3, Kerberos)
* **4672** — Special privileges assigned to logon
* **4768** — Kerberos TGT request (DC)
* **4769** — Kerberos service ticket request (CIFS)

### AD & GPO Changes

* **5136** — Directory service object modified

  * Confirmed for `groupPolicyContainer` objects
  * Validates GPO modification visibility

### Lateral Movement Indicators

* **5140** — Network share object accessed

  * Confirmed for `\\*\ADMIN$`
  * Indexed from workstation Security log
  * Correlated with network logon activity

This confirms **end-to-end visibility** from:

* Domain Controller
* Source workstation
* Target workstation

---

## 5) BloodHound — Attack Surface Mapping

### Purpose

BloodHound was used **strictly for attack path discovery**, not exploitation.

The objective was to:

* Identify misconfigurations
* Understand privilege relationships
* Validate whether the lab reflects realistic enterprise risks

---

### Data Collection

* Tool: `bloodhound-python`
* Authentication: Standard domain user
* Collection methods: `All`
* Data imported into Neo4j-backed BloodHound UI

---

### Key Findings

BloodHound analysis revealed several **high-impact AD misconfigurations**, including:

* **Unconstrained Delegation enabled on DC01**

  * Critical misconfiguration
  * Enables credential exposure and ticket abuse

* **Administrator account**

  * Member of multiple Tier-0 groups
  * `PasswordNeverExpires = true`
  * Represents a single point of total domain compromise

* **GPO modification paths**

  * Identified objects where control over GPO could lead to code execution across the domain

* **Delegated ACEs**

  * Non-admin SIDs with elevated rights on computer objects
  * Potential privilege escalation vectors

These findings confirm that the environment contains **realistic, high-risk attack paths** suitable for detection engineering and SOC-level analysis.

---

## 6) Detection Readiness Status

At the current phase, the lab has achieved the following:

 AD fully operational
 Kerberos authentication telemetry validated
 Group management and GPO changes logged
 Admin share access (`5140`) confirmed
 Sysmon stable and ingesting
 Elastic ingestion and parsing verified
 BloodHound attack paths identified

The environment is now **ready for active detection use cases**, including:

* Privilege escalation via group membership changes
* GPO abuse detection
* Identity-based lateral movement correlation

---

## 7) Next Phase (Planned)

The next stage of the lab will focus on:

* Simulating controlled privilege escalation
* Correlating:

  * 4728 / 4732 → 4672 → 5140 / 4688
* Writing Elastic SIEM detection rules
* Producing SOC-ready alerts with contextual enrichment

---
