# vt-check — VirusTotal for downloads and links

A Hermes plugin that answers two questions safely:

- **"Is this file I just downloaded safe to open?"** → hash it locally, look the SHA-256 up in
  VirusTotal, and inspect it as an archive without extracting anything.
- **"Is this link legit?"** → read-only VirusTotal URL reputation.

```bash
hermes plugins install vt-check                     # from the Hermes plugin catalog
hermes plugins enable vt-check
```

To track this repo's `main` instead of the catalog's pinned commit:

```bash
hermes plugins install Aravinth-Earth/vt-check
```

## Command line (fastest path)

The same logic also runs as a terminal command — no agent turn needed:

```bash
ln -sf "$(pwd)/bin/vt-check" ~/.local/bin/vt-check     # once

vt-check ~/Downloads/thing.zip          # one command, ~1s on a cache hit
vt-check ~/Downloads --recursive        # whole folder
vt-check --url https://example.com      # read-only URL reputation
vt-check --no-vt FILE                   # offline only: archive forensics, no network, no key
vt-check FILE --json                    # machine-readable
```

Exit codes: `0` clean · `1` suspicious/malicious · `2` unverified or error · `3` caution.
Results are cached for 24 h (`~/.cache/vt-check/cache.json`), so repeat checks are instant; the free
tier is 4 requests/min, and multiple fresh lookups are paced accordingly.

## Privacy model

| Concern | Behaviour |
|---|---|
| File contents | **Never uploaded.** The file is read locally only to compute SHA-256/SHA-1/MD5. |
| Network | Only `https://www.virustotal.com/api/v3` (hash + URL lookups, optional URL submit). |
| URL checks | Read-only `GET /urls/{base64url(url)}`. Nothing is submitted unless `submit=true`. |
| Archives | Opened **in memory**; nothing is extracted to disk. |
| Credentials | Read through Hermes (`agent.secret_scope.get_secret("VT_API_KEY")`), never from files. |
| Telemetry | None. |

## Setup

You need a free VirusTotal API key (4 requests/min, 500/day): https://www.virustotal.com/gui/my-apikey

Add it one of two ways:

1. **Desktop:** Settings → Plugins → **vt-check** → *VirusTotal API key* (masked field).
2. **Any surface:** `echo 'VT_API_KEY=<your-key>' >> ~/.hermes/.env`, then restart Hermes.

Without a key the plugin still loads, and `vt_check_file` reports the local archive findings plus an
`unverified` verdict with the setup instructions. `vt_status` tells you whether the key is valid.

## Tools

| Tool | What it does |
|---|---|
| `vt_check_file` | Hashes a file, inspects it as an archive, looks the hash up in VirusTotal, returns a merged verdict |
| `vt_check_url` | Read-only reputation for a link, **domain, or IP** — routes to `/urls`, `/domains`, `/ip_addresses`; defanged IOCs accepted |
| `vt_check_ip` | Explicit IP reputation: detections, AS owner, country, network |
| `vt_status` | Key present/valid, free-tier limits, cache TTL |

Verdicts: `malicious` → `suspicious` → `caution` → `unknown` → `clean`, plus `unverified` when there is
no key. **`unknown` is not safe** — it means nobody has scanned that build yet.

Local archive checks (work with no key and no network): path traversal (`../`, absolute paths),
decompression bombs, symlink entries, encrypted entries (contents unreadable), executables and double
extensions inside the archive (`invoice.pdf.exe`), and nested zip/tar up to depth 3. `.7z/.rar/.cab`
are flagged as uninspectable rather than silently passed.

## Settings

| Key | Type | Default | Meaning |
|---|---|---|---|
| `api_key` | secret (env `VT_API_KEY`) | — | Your VirusTotal key |
| `cache_ttl_hours` | int | 24 | How long a lookup result is reused; `0` disables caching |

Lookup results are cached in Hermes plugin state (max 200 entries), so repeated checks cost no quota.

## Disclosure (what this plugin touches)

- **Network:** calls `https://www.virustotal.com/api/v3` only, with your key. Hashes of files and the
  URLs you check (and, only with `submit=true`, the URL itself) are visible to VirusTotal.
- **Reads:** only the file paths you pass to `vt_check_file`, and the process's own credential via Hermes.
- **Writes:** lookup cache in Hermes plugin state (`<HERMES_HOME>/plugin-data/`). Nothing else.
- **No** shell commands, no background processes, no self-updater, no third-party telemetry.

## Development

```bash
python -m pytest -q                 # unit tests (no network, no Hermes needed)
./scripts/gates.sh                  # doctor + catalog validate + pytest, when Hermes is installed
```

`scripts/gates.sh` runs the same two checks catalog CI runs:
`hermes plugins doctor . --ci` and `hermes plugins validate . --install-deps`.

## Limits

Free-tier quota is 4 requests/min and 500/day; the cache exists to stay inside it. A rate-limit (HTTP
429) surfaces as a clear message instead of a retry loop. VirusTotal cannot tell you anything about a
file nobody has submitted — provenance and signature matter more there.

## Licence

MIT — see [LICENSE](LICENSE).
