# Phishing Email Triage — Microsoft 365 Credential Harvesting

A self-directed SOC analyst home-lab exercise: triaging a user-reported phishing email that impersonates Microsoft 365, building a verdict from the raw message headers down.

> **Note:** This is a hands-on training lab built on a simulated phishing sample — not a real production incident.

---

## Scenario

A user reports a suspicious "Microsoft 365 Security" email warning of unusual sign-in activity and demanding they re-verify their identity within 24 hours. Working from the raw `.eml` file, the goal is to reach a defensible verdict — is this legitimate or phishing? — and define the containment actions a SOC would take.

## Skills & tools demonstrated

- Email header analysis and **SPF / DKIM / DMARC** interpretation
- Sender spoofing detection (display name vs. real domain, Reply-To mismatch)
- URL analysis — comparing displayed link vs. actual destination, spotting lookalike domains
- Recognizing social-engineering pretexts (urgency, fear, authority)
- IOC extraction and URL **defanging**
- **Microsoft Defender for Office 365** containment workflow (message trace, ZAP, Tenant Block List)
- Triage reporting with IOCs, impact, and MITRE ATT&CK mapping

## Verdict

**Confirmed credential-harvesting phishing impersonating Microsoft 365 — High confidence**, proven across four independent indicator categories.

## Key findings

| Pillar | Finding |
|--------|---------|
| **Authentication** | SPF = fail, DKIM = none, DMARC = fail |
| **Sender** | "Microsoft 365 Security" display name over a non-Microsoft domain; Reply-To to an unrelated third domain |
| **URL** | Link displayed as `login.microsoftonline.com` but pointed to a lookalike (`m365-secure-verify[.]com`) over http, with the victim's email pre-filled |
| **Pretext** | Generic greeting, 24-hour deadline, account-suspension threat |

## Indicators of Compromise (IOCs)

- Sender IP: `193.42.61.204`
- Sender domain: `office365-support-desk[.]com`
- Reply-To domain: `mail-sec-team[.]com`
- Phishing URL: `m365-secure-verify[.]com`

## MITRE ATT&CK

`T1566.002` Phishing: Spearphishing Link · `T1598` Phishing for Information

---

## Repository contents

| File | Description |
|------|-------------|
| [`PHISHING_TRIAGE_REPORT.md`](PHISHING_TRIAGE_REPORT.md) | Full triage report — verdict, findings, IOCs, impact, containment |
| `phishing_sample.eml` | The email sample analyzed |
| `images/` | Investigation screenshots |

**➡️ Read the full triage in [PHISHING_TRIAGE_REPORT.md](PHISHING_TRIAGE_REPORT.md).**
