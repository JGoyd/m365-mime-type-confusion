# M365 Cross-Tenant MIME Type-Confusion — Inline Image Delivery Bypass

> MSRC Case 112639. No exploit code or payloads in this repo.

## Finding

An authenticated M365 tenant account can deliver arbitrary binary content
cross-tenant under `X-MS-Exchange-CrossTenant-AuthAs: Internal`, sealed by
Microsoft's `arcselector10001` ARC key, while bypassing image-specific
inspection — by declaring the attachment `application/octet-stream` with a
`.bin` filename and referencing it as an inline image via `Content-ID`
inside a `multipart/related` HTML body.

Recipient clients walk the `cid:` reference (RFC 2392) and render the bytes
as an image. Content-inspection pipelines route on the declared MIME type
and treat the same bytes as opaque binary. The declared `Content-Type` is
never normalized against the actual file bytes.

## Reference sample

Delivered through Exchange Online, 2026-04-01 01:05:35 UTC:

| Field | Value |
|---|---|
| Network Message ID | `6126db63-c140-41d2-df30-08de8f8ac828` |
| Message-ID | `<SJ0PR08MB83498BBD6B221DE976CEA90A9A50A@SJ0PR08MB8349.namprd08.prod.outlook.com>` |
| Sending Tenant GUID | `ba5a7f39-e3be-4ab3-b450-67fa80faecad` |
| Originator Org | `vanderbilt.edu` |
| Traffic Type | `SJ0PR08MB8349:EE_ \| LV3PR08MB9463:EE_` |

Attachment part:

```
Content-Type: application/octet-stream;
  name="img-558cec93-b715-4e03-9dd1-77b9d1ad276f.bin"
Content-Disposition: inline;
  filename="img-558cec93-b715-4e03-9dd1-77b9d1ad276f.bin"
Content-Transfer-Encoding: base64
Content-ID: <71286496-9DC4-4208-B54A-B40A45E951B8>
```

HTML body reference: `<img src="cid:71286496-9DC4-4208-B54A-B40A45E951B8">`.

Base64 decode → 89,872 bytes, magic `89 50 4E 47 0D 0A 1A 0A`, parses as a
valid 894×670 8-bit RGBA PNG (IHDR / sRGB / eXIf / pHYs / IDAT / IEND, all
CRCs valid).

## Trust chain (all PASS)

```
DKIM   PASS   d=vanderbilt.edu  s=selector1  2048-bit RSA-SHA256
SPF    PASS   smtp.mailfrom=vanderbilt.edu
DMARC  PASS   p=reject enforced
ARC    PASS   arcselector10001  d=microsoft.com

X-MS-Exchange-SenderADCheck:                1
X-MS-Exchange-CrossTenant-AuthAs:           Internal
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
```

## Defender for Office 365 verdict

```
SCL:1  SFV:NSPM  CAT:NONE  BCL:0
14 anti-spam rule IDs evaluated — none flagged the attachment.
```

## DKIM scope

`h=` covers `From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-SenderADCheck`.
The body hash covers the entire `multipart/mixed` / `multipart/related`
structure including the attachment's declared
`Content-Type: application/octet-stream` and base64 body. Vanderbilt's DKIM
signing cryptographically vouches for a message whose declared attachment
type contradicts its actual byte content.

## Transport chain

Every hop is Microsoft-owned infrastructure until the outbound edge:

```
SJ0PR08MB8349.namprd08.prod.outlook.com  (MAPI submission, fe80:: link-local)
  → LV3PR08MB9463.namprd08.prod.outlook.com
  → SJ2PR03CU001.outbound.protection.outlook.com [52.101.43.57]
  → recipient ingress
```

## Why it's a platform finding

| # | Behavior | Component |
|---|---|---|
| 1 | Inline image packaged as `application/octet-stream` with `.bin` filename | Outlook composition path |
| 2 | Declared `Content-Type` not normalized against actual file bytes | Exchange Online transport |
| 3 | No image-specific inspection applied to inline-referenced `octet-stream` | Defender for Office 365 |
| 4 | `CrossTenant-AuthAs: Internal` label applied across tenant boundary | Exchange Online routing |
| 5 | `arcselector10001` seals the delivery | Exchange Online ARC signing |
| 6 | Compromised legitimate tenants inherit full trust automatically via `SenderADCheck` | Exchange Online trust model |

## Reporting trail

| Date | Action |
|---|---|
| 2026-04-01 | Reported to Vanderbilt IT Security Operations — VUIT Ticket #86705. |
| 2026-04-08 | MSRC Case 112639, Update 1 — reframed around the MIME type-confusion finding. |

## Steganographic-encoding claim

The original submission referenced a transparent-pixel steganographic
encoding inside the carrier PNG. That decoding methodology is not trivially
reproducible against the delivered PNG bytes and is held as a separate open
forensic item. The finding documented here does not depend on it and is
reproducible from the raw `.eml` alone using only the Python 3 standard
library.

## CVSS

`CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:N` (8.7 High).
CWE-345, CWE-436, CWE-693, CWE-116.
