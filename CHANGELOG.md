## 0.1.5 — 2026-11-07

- Findings are now three levels: `alert` (structural, states the consequence), `warn`, and
  `info`. Executable/code files inside an archive are `info` — a source tarball or installer
  full of scripts is normal, not suspicious.
- Unseen hash no longer reads like an accusation: the text says no engine has seen that build,
  that this is normal for a new build, and that it is neither evidence of malware nor proof of
  safety. A clean local archive with an unseen hash stays `UNKNOWN`.
- Every alert now carries the concrete consequence ("extracting it writes outside the folder",
  "expands to X on extraction", "really an .exe dressed as a document").
- New check: an archive entry named like a document whose magic bytes are a PE/ELF executable.
- Cache version 3 so previously cached verdicts are re-derived.

# Changelog

## 0.1.4 — 2026-11-06

- Ratio-aware verdicts for indicators: one engine flagging an IP/domain/URL is usually a false
  positive, so `malicious` now needs ≥3 engines or ≥5% of responders; 1–2 engines reports
  `suspicious` with an explanation (seen live: `8.8.8.8` = 1/92). Files keep "any detection is a
  red flag".

## 0.1.3 — 2026-11-06

- `vt_check_url` now routes by indicator: full URLs → `/urls`, bare domains → `/domains`,
  IP addresses → `/ip_addresses`; defanged forms (`hxxps://evil[.]example`, `1.2.3[.]4`) are
  normalised first.
- New tool `vt_check_ip` for explicit IP reputation (detections, AS owner, country, network).
- CLI `--url` accepts a URL, a domain, or an IP and reports which endpoint answered.
- Tests: routing, defanging, IPv4/IPv6 classification, non-IP rejection.

## 0.1.2 — 2026-11-06

- Added a command-line entry point (`bin/vt-check` → `vtcheck.cli`): one command for files, folders,
  URLs, `--json`, `--no-vt`. Exit codes 0/1/2/3, 24 h local cache so repeat checks cost no quota, and
  free-tier pacing (4 requests/min) for fresh lookups. The CLI resolves the key from `VT_API_KEY` or
  through Hermes's own dotenv loader — it never parses `.env` itself.
- Tests for the CLI (exit codes, cache, URL path, directory walk).

## 0.1.1 — 2026-11-06

- Drop the `provides_middleware` key from `plugin.yaml`: this Hermes build does not know it and logged a
  user-visible "unknown manifest field ignored" warning at load. Added a test that pins the manifest key
  set to the runtime's known fields.

## 0.1.0 — 2026-11-05

First proper build, restructured from the throwaway prototype to the catalog's developer-guide
shape.

- Three tools: `vt_check_file`, `vt_check_url`, `vt_status`.
- Files are hashed locally (SHA-256/SHA-1/MD5) and looked up by hash — **no upload path exists**.
- URLs use VirusTotal's read-only `GET /urls/{base64url}`; `submit=true` is an explicit opt-in
  because submitting publishes the URL.
- Archive forensics in memory: path traversal, decompression bombs, symlinks, encrypted entries,
  executables and double extensions inside archives, nested zip/tar to depth 3; 7z/rar/cab are
  reported as uninspectable instead of silently passing.
- Credentials via `agent.secret_scope.get_secret("VT_API_KEY")` only (catalog rule 11) — no
  `os.environ`, no key files.
- Settings through `config_schema` (secret API-key row + `cache_ttl_hours`), lookups cached in
  `ctx.state` (200 entries max).
- `plugin.yaml` manifest v2: `requires_hermes`, `requires_env`, licence, homepage, tags.
- Tests: pure-logic, handler and manifest/registration-consistency suites (no network needed).
- Gates: `scripts/gates.sh` runs `hermes plugins doctor --ci`, `hermes plugins validate`, pytest.
