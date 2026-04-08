# M365 Steganographic Safe Attachments Bypass

> Coordinated disclosure in progress with Microsoft (MSRC submission VULN-181549).  
> No exploit code or payloads are included.

## Summary

Exchange Online / MAPI-over-HTTP allows weaponized PNG images with steganographic payloads to bypass Defender for Office 365 Safe Attachments when sent from an authenticated M365 tenant. A tested sample concealed ~9.5 KB of structured binary data in RGB channels of fully transparent pixels (alpha = 0) and was delivered as a DKIM-signed, intra-tenant message, inheriting sender trust and evading standard sandboxing.

## Impact

- Authenticated adversary in or controlling an M365 tenant can deliver zero-click surveillance or code-delivery infrastructure via trusted email.
- Payload rides the image-rendering pipeline and bypasses normal attachment inspection.

Self-assessed CVSS: `CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:N` (8.7 High).  
Related CWEs: CWE-693, CWE-116.

## Disclosure status

- Reported to MSRC on 2026-04-08 (Submission ID: VULN-181549).
- Technical artifacts (weaponized PNG, traces, PoC tooling) are **withheld** from this repo to prevent copycat exploitation.
- Full details will be considered for release after Microsoft remediation or agreed disclosure timeline.
