"""Shared fixtures: import the implementation package and fake the Hermes context."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]   # repo root
PLUGIN_DIR = ROOT / "plugin"                  # the installable Hermes plugin directory
CLI_DIR = ROOT / "bin"                        # the terminal entry point (not part of the plugin)
for _p in (PLUGIN_DIR, CLI_DIR):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from vtcheck import register, schemas, tools, vtcore  # noqa: E402


class FakeState:
    def __init__(self):
        self.data: dict = {}

    def get(self, key, default=None):
        return self.data.get(key, default)

    def set(self, key, value):
        self.data[key] = value


class FakeCtx:
    def __init__(self, config=None):
        self.tools: dict = {}
        self.skills: list = []
        self.state = FakeState()
        self.config = config or {}

    def register_tool(self, *, name, toolset, schema, handler):
        self.tools[name] = {"toolset": toolset, "schema": schema, "handler": handler}

    def register_skill(self, name, path, description=""):
        self.skills.append({"name": name, "path": Path(path), "description": description})

    def get_config(self, key, default=None):
        return self.config.get(key, default)

    def set_config(self, key, value):
        self.config[key] = value


class PluginBundle:
    """What tests see as `plugin` — the implementation modules plus register()."""

    register = staticmethod(register)
    schemas = schemas
    tools = tools
    vtcore = vtcore
    root = ROOT
    dir = PLUGIN_DIR


@pytest.fixture()
def plugin():
    return PluginBundle()


@pytest.fixture()
def ctx(plugin):
    fake = FakeCtx()
    plugin.register(fake)
    return fake
