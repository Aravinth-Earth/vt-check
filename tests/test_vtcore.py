"""Pure logic: hashing, content sniffing, archive forensics, verdict mapping, URL ids."""

from __future__ import annotations

import io
import tarfile
import zipfile
from pathlib import Path

import pytest


def test_hash_file_matches_hashlib(tmp_path, plugin):
    vt = plugin.vtcore
    p = tmp_path / "sample.txt"
    p.write_bytes(b"hello world\n")
    info = vt.hash_file(p)
    import hashlib

    assert info["sha256"] == hashlib.sha256(b"hello world\n").hexdigest()
    assert info["md5"] == hashlib.md5(b"hello world\n").hexdigest()
    assert info["size"] == 12


@pytest.mark.parametrize("head,expected", [
    (b"MZ\x90\x00", "PE/Windows executable"),
    (b"\x7fELF\x02\x01", "ELF binary"),
    (b"%PDF-1.7", "PDF document"),
    (b"PK\x03\x04", "ZIP container"),
    (b"\x1f\x8b\x08", "gzip stream"),
    (b"Rar!\x1a\x07\x00", "RAR archive"),
    (b"7z\xbc\xaf\x27\x1c", "7z archive"),
    (b"#!/bin/sh\n", "script"),
    (b"plain text", "unrecognised"),
])
def test_sniff_detects_by_magic_not_extension(head, expected, plugin):
    assert plugin.vtcore.sniff(head) == expected


def _levels(findings):
    return [f["level"] for f in findings]


def test_zip_traversal_double_extension_and_executable(tmp_path, plugin):
    vt = plugin.vtcore
    p = tmp_path / "bundle.zip"
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("../escape.sh", "#!/bin/sh\n")
        zf.writestr("invoice.pdf.exe", b"MZ\x90\x00")
        zf.writestr("notes.txt", "hi")
    findings = vt.archive_findings(p, vt.read_head(p))
    why = " ".join(f["why"] for f in findings)
    assert "path traversal" in why
    assert "double extension" in why
    assert findings and findings[0]["level"] == "alert"


def test_nested_zip_is_walked(tmp_path, plugin):
    vt = plugin.vtcore
    inner = io.BytesIO()
    with zipfile.ZipFile(inner, "w") as iz:
        iz.writestr("inner/../../trav.txt", "x")
    p = tmp_path / "outer.zip"
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("nested.zip", inner.getvalue())
    findings = vt.archive_findings(p, vt.read_head(p))
    assert any("nested.zip" in f["why"] and "traversal" in f["why"] for f in findings), findings


def test_decompression_bomb_flagged(tmp_path, plugin):
    vt = plugin.vtcore
    p = tmp_path / "bomb.zip"
    with zipfile.ZipFile(p, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("big.iso", b"\x00" * (12 * 1024 * 1024))
    findings = vt.archive_findings(p, vt.read_head(p))
    assert any("decompression bomb" in f["why"] for f in findings), findings


def test_tar_symlink_and_traversal(tmp_path, plugin):
    vt = plugin.vtcore
    p = tmp_path / "pkg.tar"
    with tarfile.open(p, "w") as tf:
        data = b"x"
        info = tarfile.TarInfo("../evil.sh")
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))
        link = tarfile.TarInfo("link")
        link.type = tarfile.SYMTYPE
        link.linkname = "/etc/passwd"
        tf.addfile(link)
    findings = vt.archive_findings(p, vt.read_head(p))
    why = " ".join(f["why"] for f in findings)
    assert "path traversal" in why and "link entry" in why


def test_thick_archive_is_reported_not_passed(tmp_path, plugin):
    vt = plugin.vtcore
    p = tmp_path / "thing.rar"
    p.write_bytes(b"Rar!\x1a\x07\x00junk")
    findings = vt.archive_findings(p, vt.read_head(p))
    assert findings and "cannot be inspected" in findings[0]["why"]


def test_non_archive_has_no_findings(tmp_path, plugin):
    vt = plugin.vtcore
    p = tmp_path / "plain.txt"
    p.write_text("hello")
    assert vt.archive_findings(p, vt.read_head(p)) == []


def test_verdict_from_stats(plugin):
    vt = plugin.vtcore
    assert vt.verdict_from_stats({"malicious": 3, "harmless": 60})[0] == "malicious"
    assert vt.verdict_from_stats({"malicious": 0, "suspicious": 2, "harmless": 60})[0] == "suspicious"
    assert vt.verdict_from_stats({"malicious": 0, "harmless": 60})[0] == "clean"


def test_merge_verdict_worst_wins(plugin):
    vt = plugin.vtcore
    warn = [{"level": "warn", "why": "x"}]
    alert = [{"level": "alert", "why": "y"}]
    assert vt.merge_verdict([], "clean") == "clean"
    assert vt.merge_verdict(warn, "clean") == "caution"
    assert vt.merge_verdict(alert, "clean") == "suspicious"
    assert vt.merge_verdict([], "malicious") == "malicious"
    assert vt.merge_verdict(alert, "malicious") == "malicious"


def test_url_id_is_vt_base64_without_padding(plugin):
    assert plugin.vtcore.url_id("http://www.google.com") == "aHR0cDovL3d3dy5nb29nbGUuY29t"
    # padding must be stripped
    assert not plugin.vtcore.url_id("https://a.b/c?d=1").endswith("=")


def test_human_bytes(plugin):
    assert plugin.vtcore.human_bytes(999) == "999B"
    assert plugin.vtcore.human_bytes(1536) == "1.5KB"


@pytest.mark.parametrize("raw,kind,value", [
    ("https://evil.example/x?y=1", "url", "https://evil.example/x?y=1"),
    ("evil.example", "domain", "evil.example"),
    ("EVIL.example.", "domain", "evil.example"),
    ("1.2.3.4", "ip", "1.2.3.4"),
    ("2001:db8::1", "ip", "2001:db8::1"),
    ("hxxps://evil[.]example/payload", "url", "https://evil.example/payload"),
    ("1.2.3[.]4", "ip", "1.2.3.4"),
    ("example.com/login", "url", "https://example.com/login"),
])
def test_normalise_target(raw, kind, value, plugin):
    got_kind, got_value = plugin.vtcore.normalise_target(raw)
    assert (got_kind, got_value) == (kind, value)


def test_indicator_lookup_routes_to_the_right_endpoint(plugin, monkeypatch):
    seen = []

    def fake_ip(key, ip, **kw):
        seen.append(("ip", ip))
        return {"status": "found", "verdict": "clean", "why": "ok"}

    def fake_domain(key, domain, **kw):
        seen.append(("domain", domain))
        return {"status": "found", "verdict": "clean", "why": "ok"}

    def fake_url(key, url, **kw):
        seen.append(("url", url))
        return {"status": "found", "verdict": "clean", "why": "ok"}

    monkeypatch.setattr(plugin.vtcore, "ip_lookup", fake_ip)
    monkeypatch.setattr(plugin.vtcore, "domain_lookup", fake_domain)
    monkeypatch.setattr(plugin.vtcore, "url_lookup", fake_url)

    plugin.vtcore.indicator_lookup("k", "8.8.8.8")
    plugin.vtcore.indicator_lookup("k", "example.com")
    plugin.vtcore.indicator_lookup("k", "https://example.com/a")
    assert seen == [("ip", "8.8.8.8"), ("domain", "example.com"), ("url", "https://example.com/a")]


def test_indicator_verdicts_tolerate_single_engine_fp(plugin):
    vt = plugin.vtcore
    assert vt.verdict_from_stats({"malicious": 1, "harmless": 90}, indicator=True)[0] == "suspicious"
    assert vt.verdict_from_stats({"malicious": 5, "harmless": 85}, indicator=True)[0] == "malicious"
    assert vt.verdict_from_stats({"malicious": 2, "undetected": 8}, indicator=True)[0] == "malicious"
    assert vt.verdict_from_stats({"malicious": 0, "harmless": 90}, indicator=True)[0] == "clean"
    # files keep the strict rule
    assert vt.verdict_from_stats({"malicious": 1, "harmless": 90})[0] == "malicious"


def test_plain_source_zip_is_not_flagged(tmp_path, plugin):
    """A legit archive with code files must not gain a security warning."""
    vt = plugin.vtcore
    p = tmp_path / "release.zip"
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("app/main.py", "print('hi')\n")
        zf.writestr("README.md", "# notes\n")
        zf.writestr("bin/tool.sh", "#!/bin/sh\necho ok\n")
    findings = vt.archive_findings(p, vt.read_head(p))
    assert all(f["level"] == "info" for f in findings), findings
    assert vt.merge_verdict(findings, "clean") == "clean"
    assert vt.merge_verdict(findings, "unknown") == "unknown"


def test_unseen_hash_stays_unknown_not_suspicious(tmp_path, plugin):
    vt = plugin.vtcore
    p = tmp_path / "fresh-build.zip"
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("app.py", "x = 1\n")
    findings = vt.archive_findings(p, vt.read_head(p))
    assert vt.merge_verdict(findings, None) in ("clean", "unknown")


def test_magic_mismatch_inside_zip_is_alert(tmp_path, plugin):
    vt = plugin.vtcore
    p = tmp_path / "docs.zip"
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("photo.pdf", b"MZ\x90\x00fake-pe")
    findings = vt.archive_findings(p, vt.read_head(p))
    assert any(f["level"] == "alert" and "named like a document" in f["why"] for f in findings), findings
