"""CLI behaviour: exit codes, cache, and the no-key path (no network)."""

from __future__ import annotations

import json
import zipfile
from pathlib import Path

import pytest


@pytest.fixture()
def cli(plugin, monkeypatch, tmp_path):
    import vt_check_cli as cli_mod

    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    return cli_mod


def test_no_key_is_unverified_and_exits_2(cli, tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(cli, "resolve_key", lambda: None)
    p = tmp_path / "a.bin"
    p.write_bytes(b"data")
    code = cli.main([str(p), "--no-vt"])
    out = capsys.readouterr().out
    assert "UNVERIFIED" in out
    assert code == 2


def test_clean_file_exits_0(cli, tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(cli, "resolve_key", lambda: "k")
    monkeypatch.setattr(cli.vt, "file_lookup", lambda key, sha, **kw: {
        "status": "found", "verdict": "clean", "why": "no detections (70 engines responded)"})
    p = tmp_path / "b.txt"
    p.write_text("hello")
    code = cli.main([str(p), "--quiet"])
    assert code == 0
    assert "CLEAN" in capsys.readouterr().out


def test_malicious_exits_1(cli, tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(cli, "resolve_key", lambda: "k")
    monkeypatch.setattr(cli.vt, "file_lookup", lambda key, sha, **kw: {
        "status": "found", "verdict": "malicious", "why": "9/70 engines flag it malicious",
        "stats": {"malicious": 9}})
    p = tmp_path / "c.bin"
    p.write_bytes(b"x")
    assert cli.main([str(p), "--quiet"]) == 1
    assert "MALICIOUS" in capsys.readouterr().out


def test_archive_findings_raise_exit_code_without_vt(cli, tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(cli, "resolve_key", lambda: None)
    p = tmp_path / "evil.zip"
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("../escape.sh", "#!/bin/sh\n")
        zf.writestr("invoice.pdf.exe", b"MZ")
    code = cli.main([str(p)])
    out = capsys.readouterr().out
    assert "path traversal" in out
    assert code == 1


def test_cache_avoids_second_request(cli, tmp_path, monkeypatch):
    calls = []

    def fake(key, sha, **kw):
        calls.append(sha)
        return {"status": "found", "verdict": "clean", "why": "ok"}

    monkeypatch.setattr(cli, "resolve_key", lambda: "k")
    monkeypatch.setattr(cli.vt, "file_lookup", fake)
    p = tmp_path / "d.txt"
    p.write_text("cache me")
    cli.main([str(p), "--quiet"])
    cli.main([str(p), "--quiet"])
    assert len(calls) == 1


def test_url_check_uses_readonly_lookup(cli, monkeypatch, capsys):
    seen = {}

    def fake(key, url, **kw):
        seen["url"] = url
        return {"status": "found", "verdict": "suspicious", "why": "2/90 engines"}

    monkeypatch.setattr(cli, "resolve_key", lambda: "k")
    monkeypatch.setattr(cli.vt, "url_lookup", fake)
    code = cli.main(["--url", "example.com", "--quiet"])
    assert seen["url"] == "https://example.com"
    assert "SUSPICIOUS" in capsys.readouterr().out
    assert code == 1


def test_json_output_shape(cli, tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(cli, "resolve_key", lambda: "k")
    monkeypatch.setattr(cli.vt, "file_lookup", lambda key, sha, **kw: {
        "status": "unknown", "verdict": "unknown", "why": "nobody scanned it"})
    p = tmp_path / "e.bin"
    p.write_bytes(b"x")
    cli.main([str(p), "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert payload["worst"] == "unknown"
    assert payload["results"][0]["sha256"]


def test_directory_walk(cli, tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(cli, "resolve_key", lambda: None)
    (tmp_path / "d").mkdir()
    (tmp_path / "d" / "one.txt").write_text("1")
    (tmp_path / "d" / "two.txt").write_text("2")
    cli.main([str(tmp_path / "d"), "--no-vt", "--quiet"])
    out = capsys.readouterr().out
    assert "one.txt" in out and "two.txt" in out
