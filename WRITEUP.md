# Mini Case Study – Brute Force + Suspicious PowerShell

## Environment
- Splunk Enterprise (trial) in Docker
- Data sources: lab:auth (SSH), lab:web (access), Sysmon-like process events
- Dashboard: SOC Lab Triage (Dashboard Studio)

## Detection 1: Brute Force (multi-IP)
**Query:**
```spl
index=main sourcetype=lab:auth action=failure
| bin _time span=3m
| stats count as failures dc(src_ip) as ips values(src_ip) as ip_list by _time user
| where failures>=3 OR ips>=2
| sort - _time
```

**Findings:** Repeated failures against `alice` and `root` from multiple IPs within short windows.

**Response (hypothetical):**
- Lock/disable targeted accounts, enforce MFA reset
- Block abusive IPs at edge
- Review successful logins around same window

**ATT&CK:** T1110 – Brute Force

---

## Detection 2: Suspicious PowerShell / LSASS
**Query:**
```spl
index=main sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational 
(CommandLine="*EncodedCommand*" OR CommandLine="*-enc *" OR CommandLine="*lsass*")
| table _time host user Image ParentImage CommandLine
```

**Findings:** Obfuscated PowerShell and LSASS MiniDump patterns surfaced in synthetic process data.

**Response (hypothetical):**
- Isolate host, capture volatile data
- Hunt for credential access, revoke tokens, rotate secrets
- Contain persistence mechanisms

**ATT&CK:** T1059.001 (PowerShell), T1003.001 (LSASS Memory)
