# Phishing Triage Report: Microsoft 365 Credential-Harvesting Email

| Field | Detail |
|---|---|
| **Report ID** | PH-2026-001 |
| **Analyst** | Swapnil |
| **Recipient** | swapnil@northwind-trading.com |
| **Reported via** | User-reported suspicious email |
| **Verdict** | **Confirmed Phishing — Credential Harvesting** |
| **Confidence** | **High** |
| **Severity** | High |
| **Impersonated brand** | Microsoft 365 |

---

## 1. Summary

A user reported a suspicious email claiming to be a "Microsoft 365 Security" alert about unusual sign-in activity, demanding identity re-verification within 24 hours. Analysis confirmed the email is **credential-harvesting phishing** impersonating Microsoft. It failed all three email-authentication checks (SPF, DKIM, DMARC), used a spoofed display name over a non-Microsoft domain, and contained a link disguised as a Microsoft login page that actually points to a lookalike credential-harvesting site. Confidence is high — the malicious intent is confirmed across four independent indicators.

---

## 2. Findings by Pillar

### Pillar 1 — Email Authentication (all failed)
- **SPF = fail** — the sending IP (`193.42.61.204`) is not authorized to send mail for the claimed domain.
- **DKIM = none** — the message carries no cryptographic signature, so its origin and integrity cannot be verified.
- **DMARC = fail (p=quarantine)** — the message failed alignment; the domain's own policy directs failing mail to be quarantined.

*All three authentication checks failing on a message claiming to be from Microsoft is a strong indicator of spoofing.*

### Pillar 2 — Sender Analysis (spoofed identity)
- **Display name vs. real address:** shows as "Microsoft 365 Security" but the actual sender is `no-reply@office365-support-desk.com` — **not** a Microsoft domain (legitimate mail comes from `microsoft.com` / `microsoftonline.com`).
- **Reply-To mismatch:** replies are directed to a third, unrelated domain — `recover-account@mail-sec-team.com`. Legitimate senders do not split the From and Reply-To across unrelated domains.
- **Mailer:** `X-Mailer: PHPMailer 6.1.7` — a bulk PHP mailing library commonly used by spammers, not Microsoft's sending infrastructure.

### Pillar 3 — URL Analysis (the smoking gun)
- **Displayed link:** `https://login.microsoftonline.com/verify-account`
- **Actual destination:** `hxxp://m365-secure-verify[.]com/login?u=swapnil@northwind-trading[.]com`
- Red flags:
  - **Display-vs-destination mismatch** — the link claims Microsoft but goes elsewhere.
  - **Lookalike domain** — `m365-secure-verify[.]com` mimics Microsoft branding but is unrelated.
  - **Victim email pre-filled** in the URL — the fingerprint of a credential-harvesting landing page.
  - **http, not https** — no encryption on a page requesting credentials; real Microsoft login is always https.

*(URLs are defanged — `hxxp`, `[.]` — to prevent accidental clicks.)*

### Pillar 4 — Content / Pretext (social engineering)
- Generic greeting ("Dear User") rather than the recipient's name.
- Manufactured urgency: a **24-hour deadline** and threat of **permanent account suspension**.
- Fear-based hook: an alarming (fake) sign-in "from Lagos, Nigeria."
- Classic urgency + fear + authority pressure designed to make the user act before thinking.

---

## 3. Indicators of Compromise (IOCs)

| Type | Indicator | Action |
|---|---|---|
| Sender IP | `193.42.61.204` | Block |
| Sender domain | `office365-support-desk.com` | Block / add to Tenant Block List |
| Reply-To domain | `mail-sec-team.com` | Block |
| Phishing URL / domain | `m365-secure-verify[.]com` | Block URL; add to Tenant Block List |

---

## 4. Impact Assessment

- If a recipient clicked the link and entered credentials, their **Microsoft 365 account would be compromised**, giving the attacker access to email, files, and any connected services.
- Compromised M365 accounts are commonly used for **business email compromise (BEC)**, internal phishing, and data theft.
- Because phishing is typically sent to many recipients, the scope must be checked across the whole tenant, not just the one reported mailbox.

---

## 5. Recommended Actions (Defender for Office 365)

**Scope**
- Use **Threat Explorer / message trace** to identify every other recipient of the same email (same sender, subject, or URL).
- Use **URL click reports** to determine whether anyone actually clicked the link.

**Contain**
- **Quarantine or soft-delete** the message from all affected mailboxes; use **ZAP (zero-hour auto purge)** to pull already-delivered copies.
- Add the sender domain and phishing URL to the **Tenant Allow/Block List**.

**Remediate (if any user submitted credentials)**
- Force a **password reset** and **revoke active sessions/tokens**.
- Inspect the mailbox for attacker-created **forwarding rules / malicious inbox rules**.
- Confirm **MFA** is enforced on the account.

**Prevent**
- Enable **Safe Links** and **Safe Attachments**, tune **anti-phishing policies**, and enforce **DMARC**.
- Reinforce user awareness on Microsoft-impersonation phishing and the "verify within 24 hours" pretext.

---

## 6. MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---|---|---|
| Initial Access | Phishing: Spearphishing Link | T1566.002 |
| Reconnaissance / Credential Access | Phishing for Information | T1598 |

---

## 7. Appendix — Methodology

Triage performed on the raw `.eml` file. Headers and authentication results extracted with `grep`; URLs extracted and the displayed-vs-actual link compared via the message's `<a href>` tags. Verdict built from four independent indicator categories (authentication, sender, URL, pretext). In a production environment the same triage is performed in Microsoft Defender for Office 365 (Threat Explorer, message trace, URL click reports).

*Prepared as a hands-on SOC analyst lab exercise (Lab 3 — Phishing Triage).*
