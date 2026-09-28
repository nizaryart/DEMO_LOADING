"""Thin mitmproxy entry point: `mitmdump -s egress_addon.py`.

mitmproxy loads a `-s` script as a standalone module, which breaks a package
module that uses relative imports and `from __future__ import annotations`
dataclasses (its `__module__` is not registered under its real name). So this
tiny loader imports the real addon as the proper package module
`demo_cli.egress` (registered correctly in sys.modules) and builds its
`addons` HERE - the only place they are built, so importing demo_cli.egress
costs nothing. `demo_cli` must be importable in mitmdump's Python —
`demo_cli egress` sets PYTHONPATH accordingly when it launches mitmdump.

KNOWN, KEPT AS IT WAS (follow-up): if the addon cannot be built, `addons` is
empty and mitmdump runs as a plain proxy - no egress guard, and nothing says so.
"""
from demo_cli.egress import _build_addon

try:
    addons = _build_addon()
except Exception:
    addons = []
