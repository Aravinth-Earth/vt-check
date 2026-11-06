---
name: vt-check
description: Vet a download or a link with VirusTotal hash lookups (files are never uploaded).
version: 0.1.0
author: Aravinth S
license: MIT
metadata:
  hermes:
    tags: [security, virustotal, malware, downloads]
---

# vt-check — is this download / link safe?

## When to use

- A file arrived from the internet (installer, `.deb`, `.AppImage`, zip, script) and the user wants to
  know whether it is safe **before** opening or extracting it.
- The user pastes a link and asks whether it is legit, phishing or malware.
- Something looks off about an archive: double extension, huge compression, encrypted contents.

## Tools

| Tool | Use it for |
|---|---|
| `vt_check_file` | Local hashes + archive forensics + SHA-256 lookup in VirusTotal. Never uploads. |
| `vt_check_url` | Read-only reputation for a link, domain, or IP; defanged IOCs OK. `submit=true` only on explicit request. |
| `vt_check_ip` | Explicit IP reputation: detections, AS owner, country, network. |
| `vt_status` | Is the key configured and valid? Free-tier limits and cache TTL. |

## Say the privacy line when it matters

A file is read locally only to compute its hashes; there is **no upload path** in this plugin. URL
checks are read-only; submitting a URL publishes it, so ask first.

## No API key

`vt_check_file` / `vt_check_url` return `error: no_api_key` with instructions. Tell the user: free key at
https://www.virustotal.com/gui/my-apikey, then Desktop → Settings → Plugins → vt-check → *VirusTotal API
key*, or `VT_API_KEY` in `~/.hermes/.env`, then restart Hermes.

## Reading the verdict

- `malicious` — at least one engine flags it. Stop; do not open.
- `suspicious` — detections or local red flags (traversal, bomb, double extension). Sandbox/VM only.
- `caution` — an executable inside the archive, encrypted entries, or an uninspectable 7z/rar.
  Normal for known software, suspicious for an unexpected download.
- `unknown` — the hash is not in VirusTotal. **Not "safe"**: fresh or mutated malware has no record.
  Fall back to provenance (official domain, package signature) and the local findings.
- `unverified` — no API key, so only local findings apply.

## Quota

Free tier: 4 requests/min, 500/day. Results are cached for the configured TTL, so re-checks are free.
On HTTP 429 tell the user to wait a minute — never retry in a loop.
