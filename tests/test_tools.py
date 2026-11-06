"""Handler behaviour: verdicts, error paths, cache and credential handling (rule 11)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest


@pytest.fixture()
def fake_http(monkeypatch, plugin):
    """Replace the single HTTP hop; records calls so cache behaviour is observable."""
    calls: list = []

    def make(response):
        def _impl(method, path, api_key, base=None, form=None, timeout=None):
            calls.append((method, path, api_key))
            return response(method, path, form) if callable(response) else response

        monkeypatch.setattr(plugin.vtcore, "http_request", _impl)
        return calls

    make.calls = calls
    return make


def _malicious(stats=None):
    return 200, {"data": {"attributes": {
        "last_analysis_stats": stats or {"malicious": 12, "harmless": 55},
        "meaningful_name": "evil.zip", "type_description": "ZIP", "size": 2048,
        "reputation": -42, "times_submitted": 9, "first_submission_date": 1700000000,
        "tags": ["trojan"],
    }}}


def _unknown(method, path, form):
    return 404, {"error": {"code": "NotFoundError"}}


@pytest.fixture()
def with_key(monkeypatch, plugin):
    monkeypatch.setattr(plugin.tools, "_secret", lambda name: "test-key")


def test_no_key_reports_unverified_and_install_help(tmp_path, plugin, ctx, monkeypatch):
    monkeypatch.setattr(plugin.tools, "_secret", lambda name: None)
    p = tmp_path / "a.txt"
    p.write_bytes(b"plain text, no archive findings")
    out = json.loads(ctx.tools["vt_check_file"]["handler"]({"path": str(p)}))
    assert out["ok"] is True
    assert out["verdict"] == "unverified"
    assert out["virustotal"]["error"] == "no_api_key"
    assert "virustotal.com/gui/my-apikey" in out["virustotal"]["help"]


def test_no_key_still_reports_local_red_flags(tmp_path, plugin, ctx, monkeypatch):
    """Offline forensics must not be downgraded to 'unverified' when it finds something."""
    monkeypatch.setattr(plugin.tools, "_secret", lambda name: None)
    p = tmp_path / "mixed.zip"
    with __import__("zipfile").ZipFile(p, "w") as zf:
        zf.writestr("../escape.sh", "#!/bin/sh\n")
    out = json.loads(ctx.tools["vt_check_file"]["handler"]({"path": str(p)}))
    assert out["verdict"] == "suspicious"
    assert out["local_verdict"] == "suspicious"


def test_key_is_read_through_secret_scope_only(monkeypatch, plugin, ctx, tmp_path):
    seen = {}

    def fake_secret(name):
        seen["name"] = name
        return "k"

    monkeypatch.setattr(plugin.tools, "_secret", fake_secret)
    monkeypatch.setattr(plugin.vtcore, "http_request", lambda *a, **kw: _malicious())
    p = tmp_path / "f.bin"
    p.write_bytes(b"data")
    ctx.tools["vt_check_file"]["handler"]({"path": str(p)})
    assert seen == {"name": "VT_API_KEY"}


def test_malicious_hash_verdict(tmp_path, plugin, ctx, with_key, fake_http):
    fake_http(lambda *a: _malicious())
    p = tmp_path / "thing.zip"
    with __import__("zipfile").ZipFile(p, "w") as zf:
        zf.writestr("readme.txt", "hi")
    out = json.loads(ctx.tools["vt_check_file"]["handler"]({"path": str(p)}))
    assert out["verdict"] == "malicious"
    assert out["virustotal"]["stats"]["malicious"] == 12
    assert out["privacy"].startswith("hashed locally")


def test_unknown_hash_is_not_clean(tmp_path, plugin, ctx, with_key, fake_http):
    fake_http(_unknown)
    p = tmp_path / "fresh.bin"
    p.write_bytes(b"brand new build")
    out = json.loads(ctx.tools["vt_check_file"]["handler"]({"path": str(p)}))
    assert out["verdict"] == "unknown"
    assert "NOT the same as safe" in out["virustotal"]["why"]


def test_local_alert_raises_verdict_even_when_vt_clean(tmp_path, plugin, ctx, with_key, fake_http):
    fake_http(lambda *a: (200, {"data": {"attributes": {
        "last_analysis_stats": {"malicious": 0, "harmless": 70}}}}))
    p = tmp_path / "mixed.zip"
    with __import__("zipfile").ZipFile(p, "w") as zf:
        zf.writestr("../escape.sh", "#!/bin/sh\n")
    out = json.loads(ctx.tools["vt_check_file"]["handler"]({"path": str(p)}))
    assert out["verdict"] == "suspicious"
    assert out["local_verdict"] == "suspicious"
    assert out["virustotal"]["verdict"] == "clean"


def test_cache_prevents_second_lookup(tmp_path, plugin, ctx, with_key, fake_http):
    calls = fake_http(lambda *a: _malicious())
    p = tmp_path / "c.bin"
    p.write_bytes(b"cache me")
    first = json.loads(ctx.tools["vt_check_file"]["handler"]({"path": str(p)}))
    second = json.loads(ctx.tools["vt_check_file"]["handler"]({"path": str(p)}))
    assert first["virustotal"]["source"] == "api"
    assert second["virustotal"]["source"] == "cache"
    assert len(calls) == 1, "a cached result must not spend quota"


def test_rate_limit_surfaces_as_actionable_error(tmp_path, plugin, ctx, with_key, fake_http):
    fake_http(lambda *a: (429, {"error": {"message": "QuotaExceededError"}}))
    p = tmp_path / "r.bin"
    p.write_bytes(b"x")
    out = json.loads(ctx.tools["vt_check_file"]["handler"]({"path": str(p)}))
    assert out["virustotal"]["error"] == "vt_error"
    assert "rate limit" in out["virustotal"]["help"].lower()


def test_bad_key_surfaces_as_vt_error(tmp_path, plugin, ctx, with_key, fake_http):
    fake_http(lambda *a: (401, {"error": {"message": "Wrong API key"}}))
    p = tmp_path / "b.bin"
    p.write_bytes(b"x")
    out = json.loads(ctx.tools["vt_check_file"]["handler"]({"path": str(p)}))
    assert out["virustotal"]["error"] == "vt_error"
    assert "my-apikey" in out["virustotal"]["help"]


def test_url_seen_and_unseen(tmp_path, plugin, ctx, with_key, fake_http, monkeypatch):
    monkeypatch.setattr(plugin.tools, "_secret", lambda n: "k")
    fake_http(lambda *a: (200, {"data": {"attributes": {
        "last_analysis_stats": {"malicious": 5, "harmless": 60},
        "categories": {"x": "phishing"}, "reputation": -5,
        "times_submitted": 3, "last_analysis_date": 1710000000}}}))
    seen = json.loads(ctx.tools["vt_check_url"]["handler"]({"url": "https://evil.example/a"}))
    assert seen["verdict"] == "malicious"
    assert seen["readonly_check"] is True

    fake_http(_unknown)
    unseen = json.loads(ctx.tools["vt_check_url"]["handler"]({"url": "https://new.example/a"}))
    assert unseen["status"] == "unknown"
    assert unseen["submitted"] is False


def test_url_submit_is_opt_in(plugin, ctx, with_key, fake_http):
    def responder(method, path, form):
        if method == "POST":
            return 200, {"data": {"id": "analysis-1"}}
        return 404, {"error": {"message": "not found"}}

    fake_http(responder)
    out = json.loads(ctx.tools["vt_check_url"]["handler"](
        {"url": "https://new.example/a", "submit": True}))
    assert out["status"] == "submitted"
    assert out["submitted"] is True
    assert "public" in out["privacy"]


def test_bare_domain_routes_to_domain_endpoint(plugin, ctx, with_key, fake_http):
    seen = {}
    fake_http(lambda method, path, form: (seen.setdefault("path", path), _unknown(method, path, form))[1])
    ctx.tools["vt_check_url"]["handler"]({"url": "example.com"})
    assert seen["path"] == "domains/example.com"


def test_input_validation(plugin, ctx, tmp_path, with_key):
    h = ctx.tools["vt_check_file"]["handler"]
    assert json.loads(h({}))["error"] == "missing_argument"
    assert json.loads(h({"path": "https://x/a.zip"}))["error"] == "use_vt_check_url"
    assert json.loads(h({"path": str(tmp_path / "nope.zip")}))["error"] == "not_found"
    assert json.loads(h({"path": str(tmp_path)}))["error"] == "is_directory"
    assert json.loads(ctx.tools["vt_check_url"]["handler"]({}))["error"] == "missing_argument"


def test_status_invalid_and_missing(plugin, ctx, fake_http, monkeypatch):
    monkeypatch.setattr(plugin.tools, "_secret", lambda n: None)
    missing = json.loads(ctx.tools["vt_status"]["handler"]({}))
    assert missing["key"] == "missing"

    monkeypatch.setattr(plugin.tools, "_secret", lambda n: "bad")
    fake_http(lambda *a: (401, {"error": {"message": "Wrong API key"}}))
    invalid = json.loads(ctx.tools["vt_status"]["handler"]({}))
    assert invalid["key"] == "invalid"


def test_handlers_never_raise_on_internal_error(plugin, ctx, with_key, monkeypatch):
    def boom(*a, **kw):
        raise RuntimeError("kaboom")

    monkeypatch.setattr(plugin.vtcore, "hash_file", boom)
    p = Path("/tmp")
    out = json.loads(ctx.tools["vt_check_file"]["handler"]({"path": "/etc/hostname"}))
    assert out["ok"] is False and out["error"] == "unreadable"


def test_cache_ttl_zero_disables_cache(plugin, ctx, with_key, fake_http, monkeypatch):
    calls = fake_http(lambda *a: _malicious())
    ctx.config["cache_ttl_hours"] = 0
    import tempfile

    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "z.bin"
        p.write_bytes(b"ttl")
        ctx.tools["vt_check_file"]["handler"]({"path": str(p)})
        second = json.loads(ctx.tools["vt_check_file"]["handler"]({"path": str(p)}))
    assert second["virustotal"]["source"] == "api"
    assert len(calls) == 2


def test_url_tool_routes_domain_to_domain_endpoint(plugin, ctx, with_key, monkeypatch):
    seen = {}
    def fake_domain(key, domain, **kw):
        seen["domain"] = domain
        return {"status": "found", "verdict": "suspicious", "why": "3/90 engines",
                "categories": {"x": "phishing"}}
    monkeypatch.setattr(plugin.vtcore, "domain_lookup", fake_domain)
    out = json.loads(ctx.tools["vt_check_url"]["handler"]({"url": "evil.example"}))
    assert seen["domain"] == "evil.example"
    assert out["queried_as"] == "domain"
    assert out["verdict"] == "suspicious"


def test_url_tool_accepts_defanged_indicator(plugin, ctx, with_key, monkeypatch):
    seen = {}
    def fake_url(key, url, **kw):
        seen["url"] = url
        return {"status": "found", "verdict": "malicious", "why": "9/90"}
    monkeypatch.setattr(plugin.vtcore, "url_lookup", fake_url)
    json.loads(ctx.tools["vt_check_url"]["handler"]({"url": "hxxps://evil[.]example/x"}))
    assert seen["url"] == "https://evil.example/x"


def test_ip_tool_happy_path(plugin, ctx, with_key, monkeypatch):
    monkeypatch.setattr(plugin.vtcore, "ip_lookup", lambda key, ip, **kw: {
        "status": "found", "verdict": "clean", "why": "0/90 engines", "as_owner": "GOOGLE"})
    out = json.loads(ctx.tools["vt_check_ip"]["handler"]({"ip": "8.8.8.8"}))
    assert out["ok"] is True
    assert out["ip"] == "8.8.8.8"
    assert out["verdict"] == "clean"
    assert out["readonly_check"] is True


def test_ip_tool_rejects_non_ip(plugin, ctx, with_key):
    out = json.loads(ctx.tools["vt_check_ip"]["handler"]({"ip": "example.com"}))
    assert out["ok"] is False and out["error"] == "not_an_ip"
    assert json.loads(ctx.tools["vt_check_ip"]["handler"]({}))["error"] == "missing_argument"


def test_ip_tool_without_key(plugin, ctx, monkeypatch):
    monkeypatch.setattr(plugin.tools, "_secret", lambda n: None)
    out = json.loads(ctx.tools["vt_check_ip"]["handler"]({"ip": "1.2.3.4"}))
    assert out["error"] == "no_api_key"
    assert "my-apikey" in out["help"]
