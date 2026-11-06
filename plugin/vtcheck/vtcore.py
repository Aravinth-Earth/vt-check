"""vtcore — VirusTotal lookups and offline archive forensics.

Pure logic: no Hermes context, no credential reads, no import-time I/O.
The caller passes the API key in; `tools.py` is the only place that resolves it.
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import re
import stat
import tarfile
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path

DEFAULT_BASE = "https://www.virustotal.com/api/v3"
MAX_ARCHIVE_DEPTH = 3
NESTED_READ_LIMIT = 32 * 1024 * 1024

EXEC_EXTS = frozenset({
    ".exe", ".dll", ".scr", ".com", ".pif", ".msi", ".msp", ".bat", ".cmd",
    ".ps1", ".psm1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta", ".lnk",
    ".jar", ".apk", ".dex", ".deb", ".rpm", ".appimage", ".run", ".sh", ".elf",
    ".so", ".dylib", ".py", ".pl", ".rb", ".php", ".iso", ".img", ".bin", ".ocx",
})
DOC_EXTS = frozenset({
    ".pdf", ".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg", ".doc", ".docx",
    ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".csv", ".rtf", ".mp3", ".mp4",
    ".mkv", ".avi", ".json", ".html", ".htm", ".xml", ".odt",
})
DOUBLE_EXT_RE = re.compile(
    r"\.(" + "|".join(sorted(e.lstrip(".") for e in DOC_EXTS)) + r")\."
    r"(" + "|".join(sorted(e.lstrip(".") for e in EXEC_EXTS)) + r")$",
    re.IGNORECASE,
)
ZIP_EXTS = frozenset({".zip", ".jar", ".apk", ".docx", ".xlsx", ".pptx", ".odt", ".epub", ".whl", ".xpi", ".crx"})
TAR_EXTS = frozenset({".tar", ".tgz", ".tbz2", ".txz"})
THICK_EXTS = frozenset({".7z", ".rar", ".cab"})

EICAR_MD5 = "44d88612fea8a8f36de82e1278abb02f"


# --------------------------------------------------------------------- helpers


def human_bytes(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if abs(n) < 1024:
            return f"{n:.0f}{unit}" if unit == "B" else f"{n:.1f}{unit}"
        n /= 1024.0
    return f"{n:.1f}TB"


def sniff(head: bytes) -> str:
    """Identify content by magic bytes — never trust the extension."""
    if head.startswith(b"MZ"):
        return "PE/Windows executable"
    if head.startswith(b"\x7fELF"):
        return "ELF binary"
    if head.startswith(b"PK\x03\x04"):
        return "ZIP container"
    if head.startswith(b"\x1f\x8b"):
        return "gzip stream"
    if head.startswith(b"7z\xbc\xaf"):
        return "7z archive"
    if head.startswith(b"Rar!"):
        return "RAR archive"
    if head.startswith(b"%PDF"):
        return "PDF document"
    if head.startswith(b"\xd0\xcf\x11\xe0"):
        return "OLE2 (legacy Office)"
    if head.startswith(b"#!"):
        return "script"
    if len(head) >= 8 and head[4:8] in (b"ftyp", b"moov", b"mdat"):
        return "MP4/QuickTime"
    return "unrecognised"


def read_head(path: Path, n: int = 4096) -> bytes:
    with path.open("rb") as fh:
        return fh.read(n)


def hash_file(path: Path) -> dict:
    """Stream the file once; return all three hashes plus the size."""
    h256, h1, h5 = hashlib.sha256(), hashlib.sha1(), hashlib.md5()
    size = 0
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            size += len(chunk)
            h256.update(chunk)
            h1.update(chunk)
            h5.update(chunk)
    return {"sha256": h256.hexdigest(), "sha1": h1.hexdigest(), "md5": h5.hexdigest(), "size": size}


# ----------------------------------------------------------- archive forensics


def _zip_findings(raw: bytes, label: str, depth: int, out: list) -> None:
    try:
        zf = zipfile.ZipFile(io.BytesIO(raw))
    except zipfile.BadZipFile:
        out.append({"level": "warn", "why": f"{label}: corrupt ZIP container"})
        return

    total = sum(i.file_size for i in zf.infolist())
    if len(raw) and total / max(len(raw), 1) > 100 and total > 10 * 1024 * 1024:
        out.append({"level": "alert",
                    "why": f"{label}: decompression bomb — {human_bytes(total)} from {human_bytes(len(raw))}"})

    for info in zf.infolist():
        name = info.filename
        parts = [p for p in re.split(r"[\\/]", name) if p]
        if name.startswith("/") or re.match(r"^[A-Za-z]:", name) or ".." in parts:
            out.append({"level": "alert", "why": f"{label}: path traversal entry '{name}'"})
        if stat.S_ISLNK((info.external_attr >> 16) & 0o170000):
            out.append({"level": "warn", "why": f"{label}: symlink entry '{name}'"})
        if info.flag_bits & 0x1:
            out.append({"level": "warn", "why": f"{label}: encrypted entry '{name}' — contents unreadable"})

        base = parts[-1] if parts else name
        if name.endswith("/") or not base:
            continue
        ext = Path(base).suffix.lower()
        if DOUBLE_EXT_RE.search(base):
            out.append({"level": "alert", "why": f"{label}: double extension '{name}'"})
        elif ext in EXEC_EXTS:
            out.append({"level": "warn",
                        "why": f"{label}: executable/script inside archive '{name}' ({human_bytes(info.file_size)})"})
        if info.file_size > 10 * 1024 * 1024 and info.file_size / max(info.compress_size, 1) > 200:
            out.append({"level": "alert", "why": f"{label}: extreme compression on '{name}'"})

        if depth < MAX_ARCHIVE_DEPTH and info.file_size <= NESTED_READ_LIMIT and ext in ZIP_EXTS:
            try:
                _zip_findings(zf.read(info), f"{label}!{base}", depth + 1, out)
            except Exception:
                out.append({"level": "info", "why": f"{label}: nested '{name}' unreadable"})


def _tar_findings(raw: bytes, label: str, depth: int, out: list) -> None:
    try:
        tf = tarfile.open(fileobj=io.BytesIO(raw), mode="r:*")
    except Exception:
        out.append({"level": "warn", "why": f"{label}: unreadable tar container"})
        return
    total = 0
    with tf:
        for member in tf:
            parts = [p for p in member.name.split("/") if p]
            if member.name.startswith("/") or ".." in parts:
                out.append({"level": "alert", "why": f"{label}: path traversal entry '{member.name}'"})
            if member.issym() or member.islnk():
                out.append({"level": "warn",
                            "why": f"{label}: link entry '{member.name}' -> '{member.linkname}'"})
            if member.isfile():
                total += member.size
                ext = Path(member.name).suffix.lower()
                if DOUBLE_EXT_RE.search(member.name):
                    out.append({"level": "alert", "why": f"{label}: double extension '{member.name}'"})
                elif ext in EXEC_EXTS:
                    out.append({"level": "warn",
                                "why": f"{label}: executable/script inside archive '{member.name}'"})
    if len(raw) and total / max(len(raw), 1) > 100 and total > 10 * 1024 * 1024:
        out.append({"level": "alert",
                    "why": f"{label}: decompression bomb — {human_bytes(total)} from {human_bytes(len(raw))}"})


def archive_findings(path: Path, head: bytes) -> list:
    """Inspect an archive in memory. Never extracts to disk."""
    findings: list = []
    ext = path.suffix.lower()
    archive_kind = None
    if head.startswith(b"PK\x03\x04") or ext in ZIP_EXTS:
        archive_kind = "zip"
    elif (head.startswith(b"\x1f\x8b") or ext in TAR_EXTS
          or path.name.lower().endswith((".tar.gz", ".tar.bz2", ".tar.xz"))):
        archive_kind = "tar"
    elif head.startswith((b"7z\xbc\xaf", b"Rar!")) or ext in THICK_EXTS:
        return [{"level": "warn",
                 "why": f"{path.name}: 7z/rar/cab cannot be inspected without external tools "
                        f"— treat the contents as unknown"}]

    if archive_kind is None:
        return findings
    try:
        if path.stat().st_size > 512 * 1024 * 1024:
            return [{"level": "warn", "why": f"{path.name}: archive too large to inspect inline"}]
        raw = path.read_bytes()
    except OSError as exc:
        return [{"level": "warn", "why": f"{path.name}: unreadable ({exc.__class__.__name__})"}]

    if archive_kind == "zip":
        _zip_findings(raw, path.name, 0, findings)
    else:
        _tar_findings(raw, path.name, 0, findings)
    return findings


# -------------------------------------------------------------------- verdicts


def verdict_from_stats(stats: dict) -> tuple[str, str]:
    total = sum(v for v in stats.values() if isinstance(v, int))
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    if malicious:
        return "malicious", f"{malicious}/{total} engines flag it malicious"
    if suspicious:
        return "suspicious", f"{suspicious}/{total} engines flag it suspicious"
    return "clean", f"no detections ({total} engines responded)"


VERDICT_RANK = {"clean": 0, "unknown": 1, "unverified": 2, "caution": 2, "suspicious": 3, "malicious": 4}


def merge_verdict(local_findings: list, vt_verdict: str | None) -> str:
    """Worst signal wins; nothing found and nothing known is 'unknown', not 'clean'."""
    level = "clean"
    if any(f.get("level") == "warn" for f in local_findings):
        level = "caution"
    if any(f.get("level") == "alert" for f in local_findings):
        level = "suspicious"
    if vt_verdict and VERDICT_RANK.get(vt_verdict, 0) > VERDICT_RANK[level]:
        level = vt_verdict
    return level


# --------------------------------------------------------------- VirusTotal


def url_id(url: str) -> str:
    """VirusTotal's URL identifier: url-safe base64 of the URL, padding stripped."""
    return base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").rstrip("=")


def http_request(method: str, path: str, api_key: str, base: str = DEFAULT_BASE,
                 form: dict | None = None, timeout: float = 30.0) -> tuple[int, dict]:
    """One HTTP round trip. Returns (status, parsed-json). status 0 = network failure.

    Isolated so tests can monkeypatch it instead of reaching the network.
    """
    data = None
    headers = {"x-apikey": api_key, "accept": "application/json",
               "user-agent": "vt-check/0.1.1 (+hermes plugin)"}
    if form:
        data = urllib.parse.urlencode(form).encode("utf-8")
        headers["content-type"] = "application/x-www-form-urlencoded"
    req = urllib.request.Request(f"{base.rstrip('/')}/{path.lstrip('/')}", data=data,
                                 headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", "replace")
        try:
            return exc.code, json.loads(body)
        except Exception:
            return exc.code, {"error": {"message": body[:200]}}
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return 0, {"error": {"message": f"network: {exc.__class__.__name__}: {exc}"}}


class VTError(Exception):
    """Raised for responses the tool layer turns into a user-facing error."""


def file_lookup(api_key: str, sha256: str, base: str = DEFAULT_BASE) -> dict:
    status, body = http_request("GET", f"files/{sha256}", api_key, base=base)
    if status == 200:
        attr = body.get("data", {}).get("attributes", {})
        stats = attr.get("last_analysis_stats", {})
        verdict, why = verdict_from_stats(stats)
        return {
            "status": "found", "verdict": verdict, "why": why, "stats": stats,
            "name": attr.get("meaningful_name") or next(iter(attr.get("names") or []), None),
            "type": attr.get("type_description"), "size": attr.get("size"),
            "reputation": attr.get("reputation"),
            "times_submitted": attr.get("times_submitted"),
            "first_seen_epoch": attr.get("first_submission_date"),
            "tags": (attr.get("tags") or [])[:8],
            "report_url": f"https://www.virustotal.com/gui/file/{sha256}",
        }
    if status == 404:
        return {"status": "unknown", "verdict": "unknown",
                "why": "hash not in VirusTotal — nobody has scanned this build yet "
                       "(unknown is NOT the same as safe)"}
    if status in (401, 403):
        raise VTError(f"VirusTotal rejected the API key (HTTP {status}). "
                      f"Update it at https://www.virustotal.com/gui/my-apikey")
    if status == 429:
        raise VTError("VirusTotal rate limit hit (free tier: 4 requests/min, 500/day). "
                      "Wait a minute and retry.")
    raise VTError(f"VirusTotal returned HTTP {status}: "
                  f"{body.get('error', {}).get('message', 'unknown error')[:200]}")


def url_lookup(api_key: str, url: str, base: str = DEFAULT_BASE) -> dict:
    uid = url_id(url)
    status, body = http_request("GET", f"urls/{uid}", api_key, base=base)
    if status == 200:
        attr = body.get("data", {}).get("attributes", {})
        stats = attr.get("last_analysis_stats", {})
        verdict, why = verdict_from_stats(stats)
        return {
            "status": "found", "verdict": verdict, "why": why, "stats": stats,
            "categories": dict(list((attr.get("categories") or {}).items())[:8]),
            "reputation": attr.get("reputation"),
            "times_submitted": attr.get("times_submitted"),
            "last_analysis_epoch": attr.get("last_analysis_date"),
            "report_url": f"https://www.virustotal.com/gui/url/{uid}",
        }
    if status == 404:
        return {"status": "unknown", "verdict": "unknown",
                "why": "this URL has never been scanned by VirusTotal (unknown is NOT safe)",
                "report_url": None}
    if status in (401, 403):
        raise VTError(f"VirusTotal rejected the API key (HTTP {status}). "
                      f"Update it at https://www.virustotal.com/gui/my-apikey")
    if status == 429:
        raise VTError("VirusTotal rate limit hit (free tier: 4 requests/min, 500/day). Wait and retry.")
    raise VTError(f"VirusTotal returned HTTP {status}: "
                  f"{body.get('error', {}).get('message', 'unknown error')[:200]}")


def url_submit(api_key: str, url: str, base: str = DEFAULT_BASE) -> dict:
    status, body = http_request("POST", "urls", api_key, base=base, form={"url": url})
    if status == 200:
        return {"status": "submitted",
                "why": "URL queued for scanning — check again in a few minutes",
                "analysis_id": body.get("data", {}).get("id")}
    if status in (401, 403):
        raise VTError(f"VirusTotal rejected the API key (HTTP {status}).")
    if status == 429:
        raise VTError("VirusTotal rate limit hit; wait a minute before submitting.")
    raise VTError(f"submit failed: HTTP {status}")
