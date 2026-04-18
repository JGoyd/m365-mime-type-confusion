# M365 Cross-Tenant MIME Type-Confusion — Invisible Inline Image Delivery Bypass

> MSRC Case 112639. No exploit code or payloads in this repo.

## Summary

A MIME type confusion in Microsoft 365 Exchange Online allows any authenticated tenant account to deliver binary content cross-tenant that bypasses all image-specific security scanning, is cryptographically signed by Microsoft's own ARC key, and renders invisibly as an email signature on mobile devices — while displaying as a visible `.bin` attachment on desktop clients.

The finding was observed in the wild on 2026-04-01 from a compromised Vanderbilt University M365 account (Vanderbilt IT ticket #86705).

## Impact

- Any compromised M365 account can deliver content through Microsoft's security pipeline without image-specific inspection. No admin access or special permissions required.
- Defender for Office 365 routes on the declared `Content-Type` (`application/octet-stream`), not the actual file bytes (valid PNG). 14 anti-spam rules evaluated the observed delivery — all passed clean.
- On iOS, the binary renders silently as a signature image through ImageIO/CoreGraphics — the same parsing pipeline targeted by FORCEDENTRY (CVE-2021-30860) — with no attachment indicator shown to the user.
- The full image (894x670 RGBA = 2.4 MB decoded) is processed for a 96x72 display — an 86.7x decode amplification through the unscanned image parser.
- Microsoft's DKIM, ARC (`arcselector10001`), SPF, DMARC, and `CrossTenant-AuthAs: Internal` all vouch for the delivery.

Self-assessed CVSS: `CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:N` (8.7 High).
Related CWEs: CWE-345, CWE-436, CWE-693, CWE-116.

## The Type Confusion

The attachment is declared as generic binary but is actually a valid PNG image:

```
Content-Type:        application/octet-stream
Content-Disposition: inline; filename="img-558cec93-b715-4e03-9dd1-77b9d1ad276f.bin"
Content-ID:          <71286496-9DC4-4208-B54A-B40A45E951B8>
```

The HTML body references it inside `<div id="ms-outlook-mobile-signature">`:

```html
<img src="cid:71286496-9DC4-4208-B54A-B40A45E951B8"
     alt="signature_3686626946" width="96" height="72"
     style="width: 1in; height: 0.75in">
```

**The scan and the render diverge:**

| Path | Interpretation | Result |
|------|---------------|--------|
| Defender (server-side) | `Content-Type: application/octet-stream` | Binary inspection only. No image scanning. **CLEAN.** |
| iOS Mail (client-side) | `cid:` resolve → byte sniff → PNG magic | ImageIO/CoreGraphics full decode. Rendered as signature image. **No attachment shown.** |

## Dual-Rendering Behavior

| Platform | What the user sees |
|----------|-------------------|
| Desktop / web client | A `.bin` attachment (87.77 KB) — visible, downloadable |
| iOS Mail / mobile | No attachment — image renders silently as a 1"x0.75" signature logo |

## Decode Amplification

The image is 894x670 pixels (8-bit RGBA) but rendered at 96x72 pixels:

| Metric | Value |
|--------|-------|
| Decoded pixel buffer | 2,395,920 bytes |
| Display size | 27,648 bytes |
| Amplification | **86.7x** |

The full 2.4 MB buffer is processed by ImageIO/CoreGraphics — the same parsing pipeline targeted by FORCEDENTRY (CVE-2021-30860) — for a 1-inch signature logo. No image-specific scanning occurred at any point.

## Observed Delivery

Delivered through Exchange Online on **2026-04-01 01:05:35 UTC**.

| Field | Value |
|-------|-------|
| Network Message ID | `6126db63-c140-41d2-df30-08de8f8ac828` |
| Sending Tenant GUID | `ba5a7f39-e3be-4ab3-b450-67fa80faecad` |
| Originator Org | `vanderbilt.edu` |
| Attachment SHA-256 | `a36cd36e56057922fb2c1d80ec7a51661602d9b9eb7afefb4dfa6853acae149f` |

Trust chain: DKIM PASS (`d=vanderbilt.edu`, `s=selector1`, 2048-bit), SPF PASS, DMARC PASS (`p=reject`), ARC PASS (`arcselector10001`, `d=microsoft.com`), `CrossTenant-AuthAs: Internal`, `SenderADCheck: 1`.

Defender verdict: `SCL:1 / SFV:NSPM / CAT:NONE / BCL:0`. 14 anti-spam rules evaluated. None flagged the attachment.

Transport: 100% Microsoft infrastructure — `SJ0PR08MB8349` → `LV3PR08MB9463` → `SJ2PR03CU001 [52.101.43.57]` → recipient.

## Platform Behaviors

| # | Behavior | Component |
|---|----------|-----------|
| 1 | Inline image packaged as `application/octet-stream` with `.bin` filename | Outlook mobile composition |
| 2 | Declared `Content-Type` not validated against actual file bytes | Exchange Online transport |
| 3 | No image-specific inspection on inline-referenced `octet-stream` | Defender for Office 365 |
| 4 | `CrossTenant-AuthAs: Internal` applied across tenant boundary | Exchange Online routing |
| 5 | `arcselector10001` ARC key seals the delivery | Exchange Online ARC signing |
| 6 | Compromised accounts inherit full trust via `SenderADCheck` | Exchange Online trust model |

## Detection

### YARA

```yara
rule M365_MIME_Type_Confusion_Inline {
    meta:
        description = "M365 email with inline image declared as octet-stream"
        reference = "MSRC 112639"
    strings:
        $mime1 = "Content-Type: application/octet-stream" ascii
        $mime2 = "Content-ID:" ascii
        $mime3 = "multipart/related" ascii
        $cid   = /src="cid:[A-Za-z0-9\-]+"/ ascii
        $png   = { 89 50 4E 47 0D 0A 1A 0A }
        $m365  = "X-MS-Exchange-CrossTenant" ascii
    condition:
        $mime1 and $mime2 and $mime3 and $cid and $png and $m365
}
```

### Exchange Online Transport Rule

**Condition:** Header contains `application/octet-stream` + body contains `cid:` + header contains `multipart/related`
**Action:** Quarantine or redirect to security team

## Verification

Every claim is reproducible from the raw `.eml` using only the Python 3 standard library. Microsoft holds the same message bytes on their servers, cross-referenced by the Network Message ID and Tenant GUID above.

## Prior Steganographic Claim

The original MSRC submission referenced a steganographic payload in transparent pixels of the carrier PNG. Byte-level analysis confirmed all 474,890 transparent pixels contain uniform white RGB (255,255,255) with zero entropy. That extraction methodology is not reproducible from the delivered file. The claim is withdrawn. The MIME type confusion finding is independently verifiable from the `.eml` alone.

## Disclosure Timeline

| Date | Event |
|------|-------|
| 2026-03-31 | In-the-wild delivery from compromised Vanderbilt University M365 account |
| 2026-04-01 | Vanderbilt IT Security notified (ticket #86705) |
| 2026-04-08 | MSRC Case 112639 filed. Update 1 with .eml and verification walkthrough same day. |
| 2026-04-09 | MSRC confirms assessment engineer assigned |
| 2026-04-10 | MSRC requests takedown of public post; complied within 2.5 hours |
| 2026-04-13 | Defensive advisory published (detection guidance, no exploit code) |
