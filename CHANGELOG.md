# Changelog

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
