"""vt-check tool handlers.

Contract: `def handler(args: dict, **kwargs) -> str`, always a JSON string, never raises.
Credentials come from Hermes only (`agent.secret_scope.get_secret`, catalog rule 11);
state comes from `ctx.state`; settings from `ctx.get_config`.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

from . import vtcore as vt

_CTX = None
CACHE_KEY = "lookup_cache"
MAX_CACHE_ENTRIES = 200
CACHE_VERSION = 2   # bump when verdict logic changes, so stale verdicts are re-derived

NO_KEY_HELP = (
    "No VirusTotal API key yet. Get a free key at https://www.virustotal.com/gui/my-apikey, then "
    "either open Hermes Desktop → Settings → Plugins → vt-check → 'VirusTotal API key', or run "
    "`hermes plugins install`/`hermes config` equivalent to set VT_API_KEY in ~/.hermes/.env, "
    "then restart Hermes."
)


def configure(ctx) -> None:
    """Called once from register(): handlers need the plugin context for state/settings."""
    global _CTX
    _CTX = ctx


# --------------------------------------------------------------- dependencies


def _secret(name: str) -> str | None:
    """Hermes-owned credential route — never os.environ, never a key file (rule 11)."""
    try:
        from agent.secret_scope import get_secret

        return get_secret(name)
    except Exception:
        return None


def _api_key() -> str | None:
    key = (_secret("VT_API_KEY") or "").strip()
    return key or None


def _cfg(key: str, default):
    if _CTX is None:
        return default
    try:
        value = _CTX.get_config(key, default=default)
    except Exception:
        return default
    return default if value is None else value


def _cache_ttl() -> int:
    try:
        hours = int(_cfg("cache_ttl_hours", 24))
    except (TypeError, ValueError):
        hours = 24
    return max(0, min(hours, 24 * 14)) * 3600


def _cache() -> dict:
    if _CTX is None:
        return {}
    try:
        return dict(_CTX.state.get(CACHE_KEY, default={}) or {})
    except Exception:
        return {}


def _cache_get(sha_or_url: str) -> dict | None:
    ttl = _cache_ttl()
    if not ttl:          # 0 = caching disabled
        return None
    entry = _cache().get(sha_or_url)
    if not entry or entry.get("v") != CACHE_VERSION:
        return None
    if time.time() - entry.get("_ts", 0) > ttl:
        return None
    return entry.get("data")


def _cache_put(sha_or_url: str, data: dict) -> None:
    if _CTX is None or not _cache_ttl():
        return
    try:
        cache = _cache()
        cache[sha_or_url] = {"_ts": time.time(), "v": CACHE_VERSION, "data": data}
        if len(cache) > MAX_CACHE_ENTRIES:
            ordered = sorted(cache.items(), key=lambda kv: kv[1].get("_ts", 0))
            cache = dict(ordered[-MAX_CACHE_ENTRIES:])
        _CTX.state.set(CACHE_KEY, cache)
    except Exception:
        pass


def _dump(payload: dict) -> str:
    return json.dumps(payload, indent=2, sort_keys=False)


def _safe(tool):
    """Last-resort guard: a tool handler must never raise into the agent loop."""
    def wrapper(args=None, **kwargs):
        try:
            return tool(args or {}, **kwargs)
        except Exception as exc:  # pragma: no cover - defensive
            return _dump({"ok": False, "error": "internal_error",
                          "help": f"{type(exc).__name__}: {exc}"})

    wrapper.__name__ = getattr(tool, "__name__", "handler")
    wrapper.__doc__ = tool.__doc__
    return wrapper


# ------------------------------------------------------------------ handlers


@_safe
def check_file(args: dict, **kwargs) -> str:
    raw = str(args.get("path") or "").strip().strip("'\"")
    if not raw:
        return _dump({"ok": False, "error": "missing_argument",
                      "help": "Pass the path of the file to check."})
    if raw.startswith(("http://", "https://")):
        return _dump({"ok": False, "error": "use_vt_check_url",
                      "help": "That is a URL, not a file. Use vt_check_url for links."})

    path = Path(raw).expanduser()
    try:
        if not path.exists():
            return _dump({"ok": False, "error": "not_found", "help": f"No such file: {path}"})
        if path.is_dir():
            return _dump({"ok": False, "error": "is_directory",
                          "help": f"{path} is a directory — pass one file or archive."})
        head = vt.read_head(path)
        info = vt.hash_file(path)
    except Exception as exc:
        return _dump({"ok": False, "error": "unreadable", "help": f"{type(exc).__name__}: {exc}"})

    content_type = vt.sniff(head)
    findings = vt.archive_findings(path, head)

    key = _api_key()
    if not key:
        vt_report: dict = {"ok": False, "error": "no_api_key", "help": NO_KEY_HELP}
    else:
        cached = _cache_get(info["sha256"])
        try:
            if cached:
                vt_report = {**cached, "ok": True, "source": "cache"}
            else:
                vt_report = {"ok": True, "source": "api", **vt.file_lookup(key, info["sha256"])}
                _cache_put(info["sha256"], vt_report)
        except vt.VTError as exc:
            vt_report = {"ok": False, "error": "vt_error", "help": str(exc)}

    verdict = vt.merge_verdict(findings, vt_report.get("verdict") if vt_report.get("ok") else None)
    if not key and verdict == "clean":
        verdict = "unverified"   # nothing found, but nothing verified either

    local_level = "clean"
    if any(f["level"] == "warn" for f in findings):
        local_level = "caution"
    if any(f["level"] == "alert" for f in findings):
        local_level = "suspicious"

    result = {
        "ok": True,
        "verdict": verdict,
        "path": str(path),
        "size_bytes": info["size"],
        "content_type": content_type,
        "hashes": {k: info[k] for k in ("sha256", "sha1", "md5")},
        "local_verdict": local_level,
        "local_findings": findings,
        "virustotal": vt_report,
        "privacy": "hashed locally; the file itself was never uploaded",
    }
    result["summary"] = _summary(result)
    return _dump(result)


def _summary(r: dict) -> str:
    parts = [f"{Path(r['path']).name}: {r['verdict'].upper()}"]
    vt_report = r.get("virustotal") or {}
    if vt_report.get("ok"):
        parts.append(vt_report.get("why") or vt_report.get("status", ""))
        if vt_report.get("report_url"):
            parts.append(vt_report["report_url"])
    elif vt_report.get("error") == "no_api_key":
        parts.append("VirusTotal not checked (no API key)")
    elif vt_report.get("help"):
        parts.append(vt_report["help"].splitlines()[0])
    if r.get("local_findings"):
        parts.append(f"{len(r['local_findings'])} archive finding(s)")
    return " | ".join(str(p) for p in parts if p)


@_safe
def check_url(args: dict, **kwargs) -> str:
    raw = str(args.get("url") or args.get("target") or "").strip()
    if not raw:
        return _dump({"ok": False, "error": "missing_argument",
                      "help": "Pass a URL, a domain, or an IP address to check."})
    submit = bool(args.get("submit", False))
    key = _api_key()
    if not key:
        return _dump({"ok": False, "error": "no_api_key", "url": raw, "help": NO_KEY_HELP})

    try:
        kind, value = vt.normalise_target(raw)
        report = vt.indicator_lookup(key, raw)
        if submit and report.get("queried_as") == "url" and report.get("status") == "unknown":
            report = {**report, **vt.url_submit(key, value)}
    except vt.VTError as exc:
        return _dump({"ok": False, "error": "vt_error", "url": raw, "help": str(exc)})

    payload = {
        "ok": True,
        "url": raw,
        "submitted": submit,
        "readonly_check": not submit,
        "privacy": ("URL submitted to VirusTotal — it is public there now" if submit
                    else "read-only lookup; nothing was submitted"),
        **report,
    }
    payload["summary"] = (
        f"{payload.get('target', raw)} ({payload.get('queried_as')}): "
        f"{str(payload.get('verdict', payload.get('status'))).upper()} — {payload.get('why', '')}"
    )
    return _dump(payload)


@_safe
def check_ip(args: dict, **kwargs) -> str:
    raw = str(args.get("ip") or "").strip()
    if not raw:
        return _dump({"ok": False, "error": "missing_argument", "help": "Pass an IPv4 or IPv6 address."})
    kind, value = vt.normalise_target(raw)
    if kind != "ip":
        return _dump({"ok": False, "error": "not_an_ip",
                      "help": f"'{raw}' is not an IP address. Use vt_check_url for links and domains."})
    key = _api_key()
    if not key:
        return _dump({"ok": False, "error": "no_api_key", "ip": value, "help": NO_KEY_HELP})
    try:
        report = vt.ip_lookup(key, value)
    except vt.VTError as exc:
        return _dump({"ok": False, "error": "vt_error", "ip": value, "help": str(exc)})
    payload = {"ok": True, "ip": value, "readonly_check": True,
               "privacy": "read-only lookup; nothing was submitted", **report}
    payload["summary"] = f"{value}: {str(payload.get('verdict', payload.get('status'))).upper()} — {payload.get('why', '')}"
    return _dump(payload)


@_safe
def status(args: dict, **kwargs) -> str:
    key = _api_key()
    if not key:
        return _dump({"ok": False, "key": "missing", "help": NO_KEY_HELP,
                      "privacy": "files are hashed locally; this plugin never uploads them"})

    try:
        probe = vt.file_lookup(key, vt.EICAR_MD5)
    except vt.VTError as exc:
        return _dump({"ok": False, "key": "invalid", "help": str(exc)})

    return _dump({
        "ok": True,
        "key": "valid",
        "probe": f"EICAR test hash resolved: {probe.get('why')} (malicious > 0 is expected)",
        "limits": "free tier: 4 requests/min, 500/day",
        "cache_ttl_hours": _cache_ttl() // 3600,
        "settings": {"cache_ttl_hours": _cfg("cache_ttl_hours", 24)},
    })
