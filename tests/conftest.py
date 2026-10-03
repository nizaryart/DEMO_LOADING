"""Suite-wide safety: no test may change a real ACL.

WHY THIS EXISTS. On 2026-09-10 the Windows suite passed 1067 tests and then
crashed in pytest's own teardown:

    PermissionError: [WinError 5] Access is denied:
    'C:\\Users\\pc\\AppData\\Local\\Temp\\pytest-of-pc\\pytest-current'

Nothing had failed. The tests had locked a temp directory for real and left
it that way, and pytest could not clean up after itself.

The mechanism: protect() and unprotect() take the lock branch when
is_elevated() says so, and MOST tests stub that - but a test only has to
forget, and on an elevated Windows run the real is_elevated answers True and
a real icacls runs against a real directory. The tests are green either way,
because the damage lands outside the assertions.

Auditing the call sites fixes today's tests and not tomorrow's. Closing the
seam fixes both: is_elevated is False for every test unless the test says
otherwise, which is what the four tests that need it already do.

A test that genuinely wants the real thing marks itself @pytest.mark.real_acl
and takes responsibility for cleaning up at the privilege it used - the same
rule that cost four failed Windows setups earlier in this project.
"""
import pytest

from demo_cli import protect as _protect


def pytest_configure(config):
    config.addinivalue_line(
        "markers", "real_acl: this test may write a real ACL; it cleans up after itself")


@pytest.fixture(autouse=True)
def _no_real_acl_writes(request, monkeypatch):
    if request.node.get_closest_marker("real_acl"):
        return
    # A test that stubs this itself overrides what is set here, and both are
    # undone at teardown.
    monkeypatch.setattr(_protect, "is_elevated", lambda: False)


import os
import shutil
import builtins
from demo_cli import recovery

ENGINE_PATH = True   # M2.1: the engine decides POSIX commands on all hosts (including Windows Git Bash)


def portable_rel(p, root, is_dir=False):
    return os.path.relpath(p, str(root)).replace(os.sep, "/") + ("/" if is_dir else "")


def assert_restores(entry, root, expected):
    """`expected` = {relpath: bytes} that the command destroys. Delete them,
    restore `entry` (any kind: file / dir / set / group), and assert each comes
    back byte-exact. Proves CONTENT, whatever the entry kind."""
    for rel in expected:
        p = os.path.join(str(root), rel)
        if os.path.isdir(p) and not os.path.islink(p):
            shutil.rmtree(p)
        elif os.path.lexists(p):
            os.remove(p)
    assert entry is not None, "REVERSIBLE claimed with no recovery entry"
    res = recovery.restore(entry)
    if hasattr(res, "ok"):
        assert res.ok, f"recovery.restore failed: {res.problem}"
    else:
        assert bool(res), "recovery.restore failed"
    for rel, data in expected.items():
        with open(os.path.join(str(root), rel), "rb") as f:
            assert f.read() == data, f"{rel} not restored byte-exact"


def sh_path(p) -> str:
    """A path as a POSIX shell word that names p on THIS host: forward
    slashes (Git Bash accepts C:/...), single-quoted. Identical to before on Linux."""
    import pathlib, shlex
    return shlex.quote(pathlib.PurePath(p).as_posix())


builtins.ENGINE_PATH = ENGINE_PATH
builtins.assert_restores = assert_restores
builtins.portable_rel = portable_rel
builtins.sh_path = sh_path
