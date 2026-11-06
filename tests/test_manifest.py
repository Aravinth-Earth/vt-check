"""Manifest + registration consistency (the checks catalog admission cares about)."""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
PLUGIN_DIR = ROOT / "plugin"


@pytest.fixture(scope="module")
def manifest():
    return yaml.safe_load((PLUGIN_DIR / "plugin.yaml").read_text())


def test_name_is_catalog_legal(manifest):
    assert re.fullmatch(r"[a-z0-9_-]{1,64}", manifest["name"]), "catalog name regex is [a-z0-9_-]{1,64}"


def test_version_is_semver(manifest):
    assert re.fullmatch(r"\d+\.\d+\.\d+", str(manifest["version"])), "version must be SemVer"


def test_manifest_v2_and_requires_hermes(manifest):
    assert manifest["manifest_version"] == 2
    assert re.fullmatch(r">=\d+\.\d+(\.\d+)?", manifest["requires_hermes"])


def test_declared_tools_match_registration(manifest, ctx):
    """Rule 6: provides_tools must be exactly what register() registers."""
    assert sorted(manifest["provides_tools"]) == sorted(ctx.tools)


def test_every_tool_has_schema_name_parameter_spec(ctx):
    for name, entry in ctx.tools.items():
        schema = entry["schema"]
        assert schema["name"] == name
        assert len(schema["description"]) > 60, f"{name}: description too thin for tool selection"
        assert "parameters" in schema and schema["parameters"].get("type") == "object"


def test_requires_env_matches_config_schema_env(manifest):
    env_names = {e["name"] if isinstance(e, dict) else e for e in manifest["requires_env"]}
    assert "VT_API_KEY" in env_names
    secret = manifest["config_schema"]["api_key"]
    assert secret["type"] == "secret"
    assert secret["env"] == "VT_API_KEY", "the settings row and the gate must name the same variable"


def test_no_self_updater_and_no_subprocess():
    """Rule 3: no self-updating code / no smuggled command execution. Cheap static guard."""
    forbidden = ("urlretrieve", "subprocess", "os.system", "pip install")
    for path in list(PLUGIN_DIR.glob("*.py")) + list((PLUGIN_DIR / "vtcheck").glob("*.py")):
        source = path.read_text()
        for token in forbidden:
            assert token not in source, f"{path.name} contains forbidden token {token!r}"


def test_no_committed_bytecode():
    """Rule 17: no unscannable payloads (pytest's own __pycache__ is not committed)."""
    def committed(directory, pattern):
        return [p for p in directory.rglob(pattern) if "__pycache__" not in p.parts]

    assert not committed(PLUGIN_DIR, "*.pyc"), "committed .pyc bytecode is rejected at admission"
    assert not committed(PLUGIN_DIR, "*.so"), "native binaries are rejected at admission"
    assert not committed(ROOT / "tests", "*.pyc")


def test_bundled_skill_registers(ctx):
    assert ctx.skills, "the bundled skill must be registered"
    skill = ctx.skills[0]
    assert skill["path"].is_file(), f"missing skill file: {skill['path']}"


def test_plugin_dir_is_self_contained():
    """Everything Hermes loads must sit in plugin/ (the catalog `subdir`)."""
    for required in ("plugin.yaml", "__init__.py", "skills/vt-check/SKILL.md"):
        assert (PLUGIN_DIR / required).exists(), f"plugin/{required} missing"
    assert not (ROOT / "plugin.yaml").exists(), "plugin.yaml must live in plugin/, not the repo root"
