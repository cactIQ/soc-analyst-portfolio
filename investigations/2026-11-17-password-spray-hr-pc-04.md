# Investigation report: Password spray from internal HR workstation

| Field | Value |
|---|---|
| Report ID | IR-2026-11-17-01 |
| Shift / scenario | Practice drill 1 (text-based, synthetic data) |
| Analyst | cactIQ |
| Date | 2026-11-17 |
| Final classification | True positive (events 4–12); benign (events 1–3) |
| Severity | High |
| Decision | Escalated to L2 / incident response |

## 1. Summary
At 09:40 UTC an internal HR computer (HR-PC-04) tried to sign in to 8 different accounts within 12 seconds using guessed passwords, a password-spraying attack. Less than a minute later, Finance user j.mehta's account signed in successfully from that same HR computer, which j.mehta does not normally use, so the account is likely compromised and the HR computer is likely controlled by an attacker. Escalated as High, with a recommendation to isolate HR-PC-04 and reset j.mehta's credentials immediately.

## 2. Alert(s)
"Multiple Windows logon failures" raised from domain controller DC01, 09:40–09:41 UTC, 10 related events from source HR-PC-04 (10.20.5.37).

## 3. Timeline
| Time (UTC) | Host | Event | Source |
|---|---|---|---|
| 09:12:03–09:12:31 | FIN-PC-02 | a.rao: 2 failed logons (wrong password), then success | DC01 Security log |
| 09:40:02 | HR-PC-04 | Spray begins: one attempt per account, ~2 s apart | DC01 Security log |
| 09:40:14 | HR-PC-04 | Spray ends: 8 failures (5 wrong password, 3 non-existent accounts) | DC01 Security log |
| 09:41:02 | HR-PC-04 | Successful network logon as j.mehta | DC01 Security log |

## 4. Evidence
- 8 failed logons (4625) from HR-PC-04 to 8 different accounts in 12 seconds: spray pattern, not a single-user error.
- 3 failures for non-existent accounts (admin, test, backup): attacker guessing common account names.
- Successful logon (4624) for j.mehta from HR-PC-04, while j.mehta's assigned workstation is FIN-PC-07.
- Source HR-PC-04 is n.patel's internal HR workstation: the attack originates inside the network.

## 5. Analysis
- Events 1–3: same account, its own assigned workstation, two failures 16 s apart then success. Consistent with a user mistyping. Benign.
- Events 4–12: one source trying many accounts with one attempt each in quick succession is the signature of password spraying. j.mehta does not appear among the failures, so the sprayed password worked for that account. A Finance user logging in from an HR machine is not normal behaviour.
- Because the source is an internal workstation, HR-PC-04 itself is probably compromised; n.patel's account may also be affected.

## 6. Severity reasoning
High: an attacker obtained valid credentials (j.mehta) and is operating from an internal host (HR-PC-04), giving a foothold for further movement. Not Critical, because j.mehta is a standard Finance user with no evidence yet of privileged access or data loss.

## 7. MITRE ATT&CK
| Tactic | Technique | Evidence item |
|---|---|---|
| Credential Access | T1110.003 Brute Force: Password Spraying | 8 failed logons across accounts from HR-PC-04 |
| Initial Access / Persistence / Defense Evasion / Privilege Escalation | T1078 Valid Accounts | Successful j.mehta logon from HR-PC-04 |

## 8. Recommendations
For L2 / IR to execute per playbook:
1. Isolate HR-PC-04 from the network.
2. Reset j.mehta's password and revoke all active sessions.
3. Review n.patel's account for compromise.
4. Investigate HR-PC-04: which process and user generated the logon attempts, and how the machine was compromised.
5. Review j.mehta's activity after 09:41:02 (other logons, file shares, mailbox, permission changes).
6. Search for the same pattern on other domain controllers and dates.

## 9. After grading
Score: 80 / 100.
- Got right: classification of both clusters, password spraying identified, ATT&CK mapping, High severity, containment actions.
- Missed initially: that an internal source means a compromised internal host; that j.mehta logged in from a machine not assigned to them; exact counts and timings (8 attempts in 12 s; success 48 s later); used "cracked" instead of "guessed"; manager summary was too technical.
- Will do differently: always compare the logon source with the user's assigned host; state exact counts and times; write summaries as what happened, impact, action.