# Incident-Response-Lab-Wazuh-SIEM-Brute-Force-Pass-the-Hash-Log-Tampering-Detection-
This lab was hands-on practice with detection and monitoring using Wazuh as a SIEM, set up against a small simulated Active Directory environment… I wanted to actually generate the attack traffic myself… and then pivot to the defender’s perspective


# Incident Response Lab (Wazuh SIEM — Brute Force, Pass-the-Hash & Log Tampering Detection)

`Wazuh` · `Kali Linux` · `Hydra` · `Windows Server / Active Directory` · `MITRE ATT&CK` · `Event Viewer` · `SMB/RDP`

## Overview
This lab was hands-on practice with **detection and monitoring** using Wazuh as a SIEM, set up against a small simulated Active Directory environment — a domain controller (`DC10`) and a client (`PC10`) — both enrolled as Wazuh agents.

Rather than just reading about how SIEMs detect attacker behavior, I wanted to actually generate the attack traffic myself from a Kali attacker box, watch it land as raw Windows Event Log entries, and then confirm Wazuh correctly correlated and alerted on it — including mapping it to the right MITRE ATT&CK technique.

I'm still early in this field, so I'm documenting the real process here: the failed commands, the typos, the permission-denied dead ends, and the eventual working attack path — not just the clean final result.

## Objective
Get comfortable on both sides of an attack: running a credential attack against a target from the attacker's perspective, and then pivoting to the defender's perspective to confirm the SIEM actually caught it, understand *why* it triggered, and map the alert back to a known adversary technique (MITRE ATT&CK).

## Environment
- **Attacker box:** Kali Linux (VM, root shell)
- **Targets:** `DC10` (`DC10.ad.structureality.com`, Windows Server, domain controller, Wazuh agent ID `002`, group `servers`) and `PC10` (Windows Server, Wazuh agent ID `001`, group `clients`)
- **SIEM:** Wazuh (deployed at `https://10.1.16.242/app/wazuh`), both agents reporting as `active`, Wazuh API v4.3.10
- **Password list source:** `/usr/share/seclists/Passwords/500-worst-passwords.txt` (SecLists), modified with a known-good credential inserted at a specific line for a controlled, reproducible test

## Tools I Used

| Tool | What It Does | Why I Used It |
|------|--------------|----------------|
| **Wazuh** | Open-source SIEM / XDR platform | Central place to correlate Windows Security event logs into alerts, dashboards, and MITRE ATT&CK mappings |
| **Hydra** | Online password brute-forcing tool | Ran a credential attack against RDP to simulate a real brute-force/credential-stuffing attempt |
| **sed** | Stream editor | Inserted a known password at a specific line of a wordlist to make the brute-force attempt reproducible and testable |
| **grep -n** | Pattern search with line numbers | Verified the injected password actually landed in the wordlist before running the attack |
| **mount / mount.cifs** | Mounts remote SMB/CIFS shares | Attempted to access the target's `C$` administrative share using discovered/candidate credentials |
| **Windows Event Viewer** | Native Windows log viewer | Cross-referenced raw Security log events (4624, 4634, 4672) against what Wazuh reported, and tested log-clearing detection |
| **MITRE ATT&CK (via Wazuh module)** | Adversary technique knowledge base | Looked up the technique Wazuh mapped the alert to, to understand *why* it was flagged and what it means |
| **Kali Linux** | Attacker VM | Environment for running Hydra and SMB mount attempts |

## What I Did

### Recon & Agent Verification
1. Confirmed both agents were online and correctly grouped in Wazuh before starting: `PC10` (001, `clients`) and `DC10` (002, `servers`), both Windows Server, both `active`.
2. Ran the Wazuh health check (`/app/wazuh#/health-check`) to confirm the API connection, index patterns, and settings were all green before trusting anything the dashboard reported.

### Building a Controlled Password List
1. Started from the SecLists `500-worst-passwords.txt` wordlist rather than hand-typing hundreds of guesses.
2. Hit a couple of path typos along the way (`/usr/share/seclist/...` instead of the correct `/usr/share/seclists/...`) — had to slow down and read `sed: can't read ... No such file or directory` carefully instead of assuming the wordlist itself was broken.
3. Used `sed` to insert a specific known password at line 57 of the list so the attack had a guaranteed, reproducible hit — useful for testing detection logic without relying on random luck:
```bash
sed '57i\Pa$$w0rd' /usr/share/seclists/Passwords/500-worst-passwords.txt > passlist.txt
```
4. Verified the insertion actually worked before running anything against a live target:
```bash
grep -n 'Pa$$w0rd' passlist.txt
# 57:Pa$$w0rd
```

### Running the Credential Attack (Hydra → RDP)
1. First attempt had a syntax error — used `-1` instead of `-l` for the login name flag:
```bash
hydra -t 1 -v -f -l administrator -P passlist.txt rdp://10.1.16.1
# hydra: invalid option -- '1'
```
2. Corrected the flag and re-ran against the RDP service on port 3389:
```bash
hydra -t 1 -v -f -l administrator -P passlist.txt rdp://10.1.16.1:3389/
```
3. Hydra returned a valid credential pair:
```
[3389][rdp] host: 10.1.16.1   login: administrator   password: Pa$$w0rd
[STATUS] attack finished for 10.1.16.1 (valid pair found)
1 of 1 target successfully completed, 1 valid password found
```

### Attempting Lateral Movement (SMB Mount)
1. Tried mounting the target's administrative share with a non-privileged account first (`jaime`) — correctly got denied, confirming the account didn't have the rights:
```bash
mkdir /mnt/dc10-c
mount -o username=jaime //10.1.16.1/c$ /mnt/dc10-c
# mount error(13): Permission denied
```
2. Retried with the credential Hydra had found (`administrator`) to see if the discovered password would grant share access.

### Confirming Detection in Wazuh
1. Switched over to the Wazuh dashboard for `DC10` and watched the alert volume change in real time as the attack ran — the "Security Alerts" total and the "Authentication failure" counter climbed from single digits into the dozens/hundreds as Hydra worked through the wordlist (peaked at **366 total events**, **56 authentication failures**, **150 authentication successes** in the 24-hour window).
2. Found the specific alert generated once the correct credential was used:

| Field | Value |
|---|---|
| Time | Jul 25, 2026 @ 06:03:10.626 |
| Rule ID | 92652 |
| Level | 6 |
| Technique | **T1550.002** |
| Tactics | Defense Evasion, Lateral Movement |
| Description | Successful Remote Logon Detected - NTLM authentication, possible pass-the-hash attack |
| Agent | DC10 (002) |

3. Opened the MITRE ATT&CK module inside Wazuh and pulled up the technique detail page for **T1550.002 — Pass the Hash**, to actually understand what the rule was flagging rather than just taking the alert title at face value: this technique covers authenticating as a user with a stolen password hash instead of a cleartext password, bypassing normal login steps entirely.
4. Cross-referenced the alert against the raw Windows Security log on `DC10` directly in Event Viewer — found the matching `4624` (Logon) and `4634` (Logoff) events, confirming Wazuh's alert lined up with what Windows itself recorded, not just a false positive from the SIEM layer.

### Testing Log-Tampering Detection
1. As a second test, cleared the Windows Security event log directly on `DC10` through Event Viewer (`Clear Log` → confirmed via the "Save and Clear / Clear / Cancel" prompt).
2. Confirmed Wazuh detected the log-clearing action itself as a distinct event, decoded via `windows_eventchannel`:

| Field | Value |
|---|---|
| Rule ID | 63103 |
| Level | 5 |
| Rule Description | The audit log was cleared |
| Rule Groups | `windows`, `windows_logs`, `log_clearing_auditlog` |
| GDPR | II_5.1.f, IV_30.1.g |

This mattered because clearing logs is a common **defense evasion** move real attackers use to cover their tracks after gaining access — confirming Wazuh catches the *clearing event itself* (rather than just going silent) means the SIEM has a chance to alert even when an attacker tries to erase evidence.

## What's in This Repo

```
incident-response-lab/
├── README.md                       # This file
├── attack/
│   └── passlist-generation.sh      # sed/grep commands used to build the controlled wordlist
├── findings/
│   ├── hydra-attack-output.txt     # Full Hydra run output (valid credential found)
│   ├── wazuh-alert-92652.json      # Pass-the-hash alert detail (rule 92652 / T1550.002)
│   ├── wazuh-alert-63103.json      # Audit log cleared alert detail (rule 63103)
│   └── dashboard-summary.txt       # Total/auth-failure/auth-success counts over the test window
└── screenshots/
    ├── 01-wazuh-agents.png
    ├── 02-hydra-attack.png
    ├── 03-wazuh-pass-the-hash-alert.png
    ├── 04-mitre-attck-t1550-002.png
    ├── 05-event-viewer-4624-4634.png
    ├── 06-log-cleared-prompt.png
    └── 07-wazuh-audit-log-cleared-alert.png
```

## Skills I Picked Up
- **Reading a SIEM alert critically instead of trusting the title** — pulling the actual MITRE ATT&CK technique page to understand *why* something was flagged as pass-the-hash rather than just seeing "possible pass-the-hash attack" and moving on.
- **Correlating SIEM alerts against raw source logs** — cross-checking a Wazuh alert against the actual Windows Security Event Viewer entries (4624/4634) it was built from, instead of assuming the SIEM's summary was automatically correct.
- **Building a controlled, reproducible credential attack** — using `sed`/`grep` to inject and verify a known password in a wordlist rather than guessing blind, so the test was repeatable and the result was explainable.
- **Reading brute-force telemetry over time** — watching authentication failure/success counters climb in the Wazuh dashboard in real time and connecting that pattern back to what the attack tool was actually doing on the wire.
- **Understanding defense evasion, not just initial access** — testing that clearing the Security log itself generates a detectable event (rule 63103), which is a distinct and important blue-team concern separate from the initial credential compromise.
- **Debugging attacker-tool syntax under pressure** — misused flags (`-1` vs `-l`), wrong file paths, and typo'd commands, and having to actually read the error text instead of guessing at a fix.

## How This Applies in the Real World
This lab mirrors a very common real-world incident response workflow: an alert fires in the SIEM, and the analyst's job is to (1) confirm it's real by checking it against raw source logs, (2) understand what technique/tactic it maps to so the response is proportional and correct, and (3) check whether the attacker tried to cover their tracks afterward.

Pass-the-hash and NTLM relay-style attacks are extremely common in real Active Directory compromises because so much lateral movement in Windows environments relies on hash-based authentication rather than cleartext passwords. Being able to recognize the Wazuh signature for it — and know it maps to **MITRE T1550.002** — is directly useful for triage: it tells you the attacker likely already has valid credentials or hashes and is moving laterally, not just guessing passwords from the outside.

Testing the log-clearing detection specifically reflects a real SOC concern: attackers who successfully get in often try to clear the Security event log to hide what they did next. A SIEM that catches the *clearing event itself* gives defenders a chance to respond even if the attacker successfully erases the log contents.

## Where I'm Coming From
I'm making the jump into cybersecurity from a background in **healthcare**. It's a different field on paper, but a lot of the muscle memory carries over — following procedures carefully, protecting sensitive information, staying calm and methodical when something isn't working the way it's supposed to. I'm currently studying for **CompTIA Security+** and building labs like this one to get real hands-on reps in, since that's what I'm missing on paper right now compared to my experience.

I'll be upfront — I'm still early in this, and there's a lot I don't know yet. I didn't get every command right on the first try (some of that's visible above — the wrong flag, the wrong file path), and I'm sure someone with more SOC experience would triage this alert faster and more thoroughly than I did. That's fine — that's kind of the point of putting this out here. I'd rather show the real process, mistakes included, than a polished version that pretends I never got stuck.

What I can say is that I actually sat down, generated the attack myself, watched it land in the SIEM, confirmed it against the raw source logs, and understood *why* it was flagged before moving on — instead of just trusting a dashboard number.

## What I Want to Learn Next
- Writing custom Wazuh detection rules from scratch, instead of relying only on the built-in ruleset
- Building out a proper incident timeline/report from raw alert data (who, what, when, how it was detected, how it was contained)
- Testing detection against a wider range of MITRE ATT&CK techniques (privilege escalation, persistence, exfiltration) in the same lab environment
- Integrating Wazuh with an alerting channel (email/Slack/webhook) so alerts don't just sit in a dashboard waiting to be checked manually
- Practicing full incident response phases — containment, eradication, and recovery — not just detection

## Limitations & What I'd Do Differently in Production
Being honest about the gaps here, because I think that matters more than pretending this is finished:

- **The credential attack used a wordlist with the answer deliberately inserted.** That was intentional for a controlled, reproducible test, but it means this isn't a realistic measure of how long a real brute-force attempt against a strong password would take.
- **No account lockout policy was in play.** In a real environment, 56+ failed authentication attempts against a single account in a short window should trigger an account lockout well before an attacker gets through a wordlist — that control wasn't tested here.
- **No automated response.** Wazuh alerted correctly, but nothing automatically blocked the attacking IP or disabled the account. In production I'd want this tied into an active response (like the automated `iptables` blocking in my other lab) rather than requiring a human to notice and act.
- **Single test window, single account.** This lab tested one account against one service (RDP). A real assessment would test password spraying across multiple accounts and multiple services (SMB, WinRM, RDP) to get a fuller picture of exposure.
- **The SMB mount attempt wasn't fully validated end-to-end** in this write-up — the permission-denied result for the non-privileged account is well documented, but the follow-up attempt with the discovered credential needs to be captured just as clearly for a complete picture of what lateral movement was actually achievable.
- **No log-forwarding hardening.** If an attacker can clear the local Security log, in a hardened production environment logs should also be forwarded to a remote/immutable log store in near-real-time so local clearing doesn't destroy the only copy of the evidence.

I'm listing these out on purpose — not because I think they make the lab look bad, but because I'd rather show that I understand where the rough edges are than have someone else find them first.

## References
- [Wazuh Documentation](https://documentation.wazuh.com/)
- [MITRE ATT&CK — T1550.002: Pass the Hash](https://attack.mitre.org/techniques/T1550/002/)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Hydra — GitHub (van Hauser/THC)](https://github.com/vanhauser-thc/thc-hydra)
- [SecLists — GitHub (danielmiessler)](https://github.com/danielmiessler/SecLists)
- [GNU sed manual](https://www.gnu.org/software/sed/manual/sed.html)
- [Microsoft — Windows Security Event ID 4624/4634 reference](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624)
- [Microsoft — mount.cifs / SMB share access](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-overview)
- [CompTIA Security+ (SY0-701) Exam Objectives](https://www.comptia.org/certifications/security)
- [NIST SP 800-61 Rev. 2 — Computer Security Incident Handling Guide](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final)
- Kali Linux — attacker VM environment used throughout
- Wazuh — SIEM platform used throughout
