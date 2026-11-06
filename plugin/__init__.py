"""vt-check — VirusTotal reputation for downloads and links (hash-only, never uploads).

Hermes loads this package and calls `register(ctx)`. The implementation lives in the
`vtcheck` subpackage so it can also be imported by tests as a normal Python package.
"""

from __future__ import annotations

from .vtcheck import register  # noqa: F401  (re-exported for Hermes)

__all__ = ["register"]
