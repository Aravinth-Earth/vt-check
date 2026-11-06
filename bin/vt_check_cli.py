"""vt-check CLI — the one-command path for a terminal.

    vt-check FILE...            check files/archives (hash + archive forensics)
    vt-check --url URL          read-only URL reputation
    vt-check --json FILE        machine-readable
    vt-check --no-vt FILE       offline only (no network, no key)

Exit codes: 0 clean | 1 suspicious/malicious | 2 unverified or error | 3 caution
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

from vtcheck import vtcore as vt

RANK = {"clean": 0, "unknown": 1, "unverified": 2, "caution": 2, "suspicious": 3, "malicious": 4}
EXIT = {"clean": 0, "caution": 3, "suspicious": 1, "malicious": 1, "unknown": 2, "unverified": 2, "error": 2}
FREE_TIER_GAP = 16.0   # 4 requests/min
CACHE_TTL = 24 * 3600


def _cache_path() -> Path:
    base = os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    return Path(base) / "vt-check" / "cache.json"


def _cache_load() -> dict:
    try:
        return json.loads(_cache_path().read_text())
    except Exception:
        return {}


def _cache_save(cache: dict) -> None:
    try:
        p = _cache_path()
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_suffix(".tmp")
        tmp.write_text(json.dumps(cache))
        os.replace(tmp, p)
    except Exception:
        pass


def _cached(cache: dict, key: str) -> dict | None:
    entry = cache.get(key)
    if entry and time.time() - entry.get("_ts", 0) < CACHE_TTL:
        return entry.get("data")
    return None


def _store(cache: dict, key: str, data: dict) -> None:
    cache[key] = {"_ts": time.time(), "data": data}
    if len(cache) > 500:
        keep = sorted(cache.items(), key=lambda kv: kv[1].get("_ts", 0))[-500:]
        cache.clear()
        cache.update(dict(keep))
    _cache_save(cache)


def resolve_key() -> str | None:
    """Terminal path: env var, else Hermes's own profile loader (never parse .env ourselves)."""
    key = os.environ.get("VT_API_KEY", "").strip()
    if key:
        return key
    try:  # only when a Hermes install is reachable
        from hermes_cli.env_loader import load_hermes_dotenv  # type: ignore

        load_hermes_dotenv()
        from agent.secret_scope import get_secret  # type: ignore

        return (get_secret("VT_API_KEY") or "").strip() or None
    except Exception:
        return None


def human(n: float) -> str:
    return vt.human_bytes(n)


def check_one(path: Path, key: str | None, cache: dict | None = None) -> tuple[dict, bool]:
    """Returns (result, cache_hit)."""
    head = vt.read_head(path)
    info = vt.hash_file(path)
    findings = vt.archive_findings(path, head)
    local = "clean"
    if any(f["level"] == "warn" for f in findings):
        local = "caution"
    if any(f["level"] == "alert" for f in findings):
        local = "suspicious"

    rec: dict = {}
    hit = False
    if key:
        cached = _cached(cache, info["sha256"]) if cache is not None else None
        if cached:
            rec, hit = cached, True
        else:
            try:
                rec = vt.file_lookup(key, info["sha256"])
            except vt.VTError as exc:
                rec = {"status": "error", "why": str(exc)}
            if cache is not None and rec.get("status") in ("found", "unknown"):
                _store(cache, info["sha256"], rec)
    if not key:
        merged = vt.merge_verdict(findings, None)
        verdict = merged if merged != "clean" else "unverified"
    else:
        verdict = vt.merge_verdict(findings, rec.get("verdict"))
    return {
        "path": str(path), "size": info["size"], "sha256": info["sha256"],
        "content_type": vt.sniff(head), "local_verdict": local, "local_findings": findings,
        "virustotal": rec, "verdict": verdict,
    }, hit


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="vt-check",
        description="Vet downloads and links with VirusTotal hash lookups (files are never uploaded).",
    )
    ap.add_argument("targets", nargs="*", help="files or directories")
    ap.add_argument("--url", action="append", default=[], help="check a URL instead of a file (repeatable)")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--no-vt", action="store_true", help="offline only: no network, no key needed")
    ap.add_argument("--recursive", action="store_true", help="walk directories recursively")
    ap.add_argument("--quiet", action="store_true", help="one line per file")
    args = ap.parse_args(argv)

    if not args.targets and not args.url:
        ap.print_help()
        return 2

    key = None if args.no_vt else resolve_key()
    if not args.no_vt and not key:
        print("No VirusTotal key. Set VT_API_KEY, or add it in Hermes (Settings → Plugins → vt-check).",
              file=sys.stderr)
        print("Continuing with offline checks only.\n", file=sys.stderr)

    results: list[dict] = []
    total = 0
    paths: list[Path] = []
    for t in args.targets:
        p = Path(t).expanduser()
        if p.is_dir():
            it = p.rglob("*") if args.recursive else p.glob("*")
            paths.extend(sorted(f for f in it if f.is_file()))
        else:
            paths.append(p)
    total = len(paths) + len(args.url)

    cache = _cache_load() if key else None

    for path in paths:
        if not path.exists():
            results.append({"path": str(path), "verdict": "error", "why": "no such file"})
            continue
        try:
            res, hit = check_one(path, key, cache)
            results.append(res)
        except Exception as exc:
            results.append({"path": str(path), "verdict": "error", "why": f"{type(exc).__name__}: {exc}"})
            hit = False
        if key and not hit and len(results) < total:
            time.sleep(FREE_TIER_GAP)   # free tier is 4 requests/min

    for url in args.url:
        if not key:
            results.append({"url": url, "verdict": "unverified", "why": "no API key"})
            continue
        normalised = url if "://" in url else f"https://{url}"
        cached = _cached(cache, normalised) if cache is not None else None
        if cached:
            results.append({"url": url, "verdict": cached.get("verdict", cached.get("status")),
                            "virustotal": {**cached, "status": cached.get("status", "found")}})
            continue
        try:
            rec = vt.url_lookup(key, normalised)
            if cache is not None and rec.get("status") in ("found", "unknown"):
                _store(cache, normalised, rec)
            results.append({"url": url, "verdict": rec.get("verdict", rec.get("status")),
                            "virustotal": rec})
        except vt.VTError as exc:
            results.append({"url": url, "verdict": "error", "why": str(exc)})
        if total > 1:
            time.sleep(FREE_TIER_GAP)

    worst = "clean"
    for r in results:
        if RANK.get(r["verdict"], 0) > RANK[worst]:
            worst = r["verdict"]

    if args.json:
        print(json.dumps({"worst": worst, "results": results}, indent=2))
    else:
        for r in results:
            raw = r.get("path") or r.get("url") or "?"
            name = Path(raw).name or raw
            vtinfo = r.get("virustotal") or {}
            why = vtinfo.get("why") or r.get("why") or ""
            line = f"{r['verdict'].upper():11} {name[:48]:50} {why[:70]}"
            if args.quiet:
                print(line)
            else:
                print(f"\n{name}  [{human(r.get('size', 0))}, {r.get('content_type', '?')}]")
                print(f"  sha256  {r.get('sha256', '-')}")
                for f in r.get("local_findings", []):
                    print(f"  {'!!' if f['level'] == 'alert' else ' !'} {f['why']}")
                if vtinfo:
                    print(f"   VT  {str(vtinfo.get('status', '')).upper()} — {why}")
                print(f"  => {r['verdict'].upper()}")
        if len(results) > 1:
            counts: dict = {}
            for r in results:
                counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1
            print("\nsummary: " + ", ".join(f"{k}={v}" for k, v in sorted(counts.items())))

    return EXIT.get(worst, 2)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
