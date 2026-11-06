"""vt-check implementation: schemas, tool handlers, and the VirusTotal client."""

from __future__ import annotations

import logging
from pathlib import Path

from . import schemas, tools

logger = logging.getLogger(__name__)

# Plugin root (the directory holding plugin.yaml and skills/)
PLUGIN_ROOT = Path(__file__).resolve().parent.parent


def register(ctx):
    """Wire the three tools and the bundled skill into Hermes."""
    tools.configure(ctx)

    ctx.register_tool(name="vt_check_file", toolset="virustotal",
                      schema=schemas.CHECK_FILE, handler=tools.check_file)
    ctx.register_tool(name="vt_check_url", toolset="virustotal",
                      schema=schemas.CHECK_URL, handler=tools.check_url)
    ctx.register_tool(name="vt_check_ip", toolset="virustotal",
                      schema=schemas.CHECK_IP, handler=tools.check_ip)
    ctx.register_tool(name="vt_status", toolset="virustotal",
                      schema=schemas.STATUS, handler=tools.status)

    skill_md = PLUGIN_ROOT / "skills" / "vt-check" / "SKILL.md"
    if skill_md.is_file():
        ctx.register_skill("vt-check", skill_md,
                           description="Vet downloads and links with VirusTotal hash lookups "
                                       "(files are never uploaded).")
    else:  # pragma: no cover - packaging accident
        logger.warning("vt-check: bundled skill missing at %s", skill_md)
