"""Run an agent with every layer that can be brought up, brought up.

--------------------------------------------------------------------------
WHY THIS EXISTS
--------------------------------------------------------------------------
Setup had become four separate things with four different lifetimes: hooks
(persistent, per host), the filesystem mount (detached, needs admin), the
egress proxy (a second terminal), and environment variables (per shell). A
person has to remember all four, and nothing tells them how many are actually
on. "Installed but inert" has been the dangerous state five times in this
project; four independent setup steps is how a sixth happens.

The agent is the unit being guarded, so one command brings up what it can for
exactly that agent's lifetime, REPORTS THE COVERAGE HONESTLY, and launches it.

    demo_cli guarded claude

--------------------------------------------------------------------------
WHY ENVIRONMENT VARIABLES REACH A FRESH SHELL
--------------------------------------------------------------------------
Claude Code spawns a new `powershell -NoProfile` (or bash) for every tool
call, and we verified that a variable set INSIDE one tool call is gone by the
next - each shell dies with its call. That is siblings.

This sets the variables one level UP, on the agent process itself:

    demo_cli guarded claude
      └─ claude                  <- environment set here, once
           ├─ powershell         <- inherits
           │    └─ python        <- inherits
           └─ powershell         <- inherits (new shell, same parent)

Every fresh shell is a child of the agent, so it inherits at spawn. -NoProfile
skips profile SCRIPTS; it does not clear the environment.

Which is also why only two layers need this. The mount is a PATH - anything
touching it is guarded with nothing to inherit - and hooks are config files the
host reads. Only egress and the bash shell guard travel through the
environment.

--------------------------------------------------------------------------
WHAT IT WILL NOT DO
--------------------------------------------------------------------------
Start the mount        it needs elevation, and the project has to have been
                       relocated first (`demo_cli protect`). Silently moving
                       somebody's project because they typed `guarded` is not
                       a thing this should do.
Install hooks          they are persistent host config. Verified, never
                       written behind the user's back.
Trust the CA           a root CA must never appear on a machine without being
                       asked for.
Everything it cannot start, it REPORTS. A layer that is off should be visible
at the moment the agent launches, not discoverable later by running doctor.
"""
from __future__ import annotations

import os
import socket
from dataclasses import dataclass
from typing import Dict, List, Optional

from .config import Config

# Hostnames that must never route through the egress proxy:
#   1. Localhost and loopbacks: dev servers and the guard's own port.
#   2. AI model inference endpoints: Anthropic, OpenAI, Google Gemini.
#      The agent's own thinking/control stream must never be buffered, delayed,
#      or broken by egress TLS interception.
_DEFAULT_NO_PROXY_LIST = [
    "localhost",
    "127.0.0.1",
    "::1",
    "api.anthropic.com",
    "api.openai.com",
    "generativelanguage.googleapis.com",
    "*.anthropic.com",
    "*.openai.com",
]
_NO_PROXY = ",".join(_DEFAULT_NO_PROXY_LIST)


def default_no_proxy(extra: Optional[List[str]] = None) -> str:
    """Return the comma-separated NO_PROXY list, including localhost,
    LLM provider API endpoints, and any extra hosts specified."""
    hosts = list(_DEFAULT_NO_PROXY_LIST)
    if extra:
        for h in extra:
            if h and h not in hosts:
                hosts.append(h)
    return ",".join(hosts)


@dataclass
class Layer:
    """One protection layer, and whether it is actually on right now."""
    name: str
    ok: bool
    detail: str
    fixable: Optional[str] = None      # the command that would turn it on


def port_open(port: int, host: str = "127.0.0.1", timeout: float = 0.4) -> bool:
    """Is something listening? The only honest test for 'is the proxy up'.

    A recorded pid would not do: mitmdump is started separately, may be run by
    hand in another terminal, and may have died. Connecting is the question
    actually being asked.
    """
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def ca_bundle() -> Optional[str]:
    path = os.path.normpath(
        os.path.join(os.path.expanduser("~/.mitmproxy"), "mitmproxy-ca-cert.pem"))
    return path if os.path.exists(path) else None


BUNDLE_NAME = "demo_cli-ca-bundle.pem"

# Variables that REPLACE a client's trust store rather than adding to it.
# They must be given the combined bundle, never the bare CA.
_REPLACING_CA_VARS = ("REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "SSL_CERT_FILE",
                      "GIT_SSL_CAINFO", "AWS_CA_BUNDLE")


def _pem_blocks(text: str) -> List[str]:
    out, cur = [], []
    for line in text.splitlines():
        if line.startswith("-----BEGIN CERTIFICATE"):
            cur = [line]
        elif cur:
            cur.append(line)
            if line.startswith("-----END CERTIFICATE"):
                out.append("\n".join(cur))
                cur = []
    return out


def _public_roots() -> List[str]:
    """The machine's normal trust anchors, as PEM blocks.

    Both sources, unioned. certifi is the curated set requests itself uses;
    the OS store carries corporate roots certifi does not. On Windows the OS
    store is populated ON DEMAND, so it reported 52 roots where Linux reported
    150 - building from it alone would omit roots the machine would otherwise
    fetch, and we would cause TLS failures that do not happen without us.
    """
    blocks: List[str] = []
    try:
        import certifi
        with open(certifi.where(), encoding="utf-8") as fh:
            blocks += _pem_blocks(fh.read())
    except Exception:
        pass
    try:
        import ssl
        for der in ssl.create_default_context().get_ca_certs(binary_form=True):
            blocks.append(ssl.DER_cert_to_PEM_cert(der).strip())
    except Exception:
        pass
    return blocks


def combined_ca_bundle() -> Optional[str]:
    """Path to `public roots + the mitmproxy CA`, or None.

    REQUESTS_CA_BUNDLE and friends REPLACE the trust store - measured, 1 root
    against the default 150. Pointing them at the bare CA makes every DIRECT
    connection fail, which is exactly the traffic NO_PROXY exists to protect:
    the agent reaches api.anthropic.com without the proxy, and the one root it
    is allowed to trust is not the one that signed it.

    Rebuilt on every call and replaced atomically: it is cheap, it cannot go
    stale against a rotated CA, and concurrent runs cannot see a partial file.
    None on any failure, so the caller sets nothing - a client with no override
    still reaches the internet, it just cannot see through the proxy.
    """
    ca = ca_bundle()
    if not ca:
        return None
    try:
        with open(ca, encoding="utf-8") as fh:
            mitm = _pem_blocks(fh.read())
        if not mitm:
            return None
        seen, ordered = set(), []
        for block in _public_roots() + mitm:
            if block not in seen:
                seen.add(block)
                ordered.append(block)
        dest = os.path.join(os.path.dirname(ca), BUNDLE_NAME)
        tmp = dest + f".{os.getpid()}.tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write("\n".join(ordered) + "\n")
        os.replace(tmp, dest)
        return dest
    except Exception:
        return None


def proxy_process_env(base: Dict[str, str]) -> Dict[str, str]:
    """The environment mitmdump itself is started with.

    The CA overrides are STRIPPED. mitmdump inherits os.environ, so a shell
    that exported REQUESTS_CA_BUNDLE or SSL_CERT_FILE - which the setup lines
    tell people to do - would hand the proxy a trust store it must not use for
    its own upstream connections. Pointed at a bare CA it could then verify no
    server at all.
    """
    env = dict(base)
    for var in _REPLACING_CA_VARS:
        env.pop(var, None)
        env.pop(var.lower(), None)
    return env


def shell_guard_script() -> Optional[str]:
    path = os.path.expanduser("~/.demo_cli_shellguard.sh")
    return path if os.path.exists(path) else None


def child_env(base: Dict[str, str], port: int, egress_up: bool,
              extra_no_proxy: Optional[List[str]] = None,
              config: Optional[Config] = None) -> Dict[str, str]:
    """The environment the agent is launched with.

    Only variables whose layer is ACTUALLY RUNNING are set. Pointing
    HTTPS_PROXY at a dead port is the footgun that makes people uninstall the
    tool: every network call in every child then fails, long after anyone
    remembers setting it. This is also why the variables are scoped to the
    child instead of written with setx - they cannot outlive the thing they
    describe.
    """
    env = config.sanitized_env(base) if config else dict(base)
    if egress_up:
        env["HTTPS_PROXY"] = env["https_proxy"] = f"http://localhost:{port}"
        env["HTTP_PROXY"] = env["http_proxy"] = f"http://localhost:{port}"
        existing = [h.strip() for h in (base.get("NO_PROXY") or base.get("no_proxy") or "").split(",") if h.strip()]
        all_extra = (existing or []) + (extra_no_proxy or [])
        no_p = default_no_proxy(all_extra) if all_extra else _NO_PROXY
        env["NO_PROXY"] = env["no_proxy"] = no_p
        ca = ca_bundle()
        if ca:
            # NODE_EXTRA_CA_CERTS ADDS to Node's built-in roots, so the bare
            # CA is correct for it. Everything else REPLACES the trust store
            # and needs the combined bundle - see combined_ca_bundle.
            env["NODE_EXTRA_CA_CERTS"] = ca
            bundle = combined_ca_bundle()
            if bundle:
                for var in _REPLACING_CA_VARS:
                    env[var] = bundle
    guard = shell_guard_script()
    if guard and os.name != "nt":
        # Makes a non-interactive `bash -c` source the DEBUG trap - the same
        # mechanism install-shell-guard writes into .bashrc, scoped here to
        # the agent instead of to every shell the human opens.
        env["BASH_ENV"] = guard
    return env


def assess(cfg: Config, port: int, hooks: List[tuple],
           egress_up: Optional[bool] = None) -> List[Layer]:
    """Which layers are protecting this project, right now.

    `hooks` comes from the caller (cli._host_hook_status) so this module stays
    free of the CLI's host table, and the whole function stays testable
    without a filesystem full of host configs.
    """
    from . import fsmount, mountstate, protect as protect_mod

    layers: List[Layer] = []

    installed = [label for label, path in hooks if path]
    layers.append(Layer(
        "string layer", bool(installed),
        f"hook active ({', '.join(installed)})" if installed
        else "no host hook installed - tool calls are not classified",
        None if installed else "demo_cli install-hook"))

    st = mountstate.status(cfg)
    if st.running:
        locked = protect_mod.is_locked(st.backing) if st.backing else None
        note = (" (backing locked)" if locked else
                " (backing NOT locked - writable directly)" if locked is False else "")
        layers.append(Layer("filesystem", True, f"mounted at {st.mountpoint}{note}"))
    elif st.stale:
        layers.append(Layer("filesystem", False,
                            f"RECORDED BUT NOT RUNNING (pid {st.pid} is gone)",
                            "demo_cli unmount, then demo_cli mount ..."))
    elif os.name == "nt":
        # A protected project that is not mounted needs a DIFFERENT remedy
        # from an unprotected one, and telling somebody to protect a project
        # that is already protected reads as the tool not knowing its own
        # state.
        protected = os.path.isdir(protect_mod.backing_for(cfg.project_root))
        layers.append(Layer(
            "filesystem", False,
            "protected but not mounted" if protected else "not mounted",
            "demo_cli mount (elevated), or it returns at your next logon"
            if protected else "demo_cli setup"))
    else:
        # No always-on equivalent on Linux: the syscall guard wraps one command
        # rather than standing between the agent and the disk.
        layers.append(Layer("filesystem", False,
                            "no always-on layer on Linux; use demo_cli run <cmd>"))

    up = port_open(port) if egress_up is None else egress_up
    ca = ca_bundle()
    # A proxy with no CA is not a layer that protects anything: every TLS
    # handshake through it fails. It used to be reported ok with the problem
    # in the detail string, so coverage counted it.
    layers.append(Layer(
        "egress", up and bool(ca),
        (f"proxy on :{port}" if ca
         else f"proxy on :{port}, but no CA yet - TLS will fail")
        if up else f"nothing listening on :{port}",
        None if up else f"demo_cli egress --port {port}"))

    if os.name != "nt":
        guard = shell_guard_script()
        layers.append(Layer("shell guard", bool(guard),
                            guard or "not installed - !-mode is unguarded",
                            None if guard else "demo_cli install-shell-guard"))
    return layers


def summary(layers: List[Layer]) -> str:
    on = sum(1 for x in layers if x.ok)
    return f"{on} of {len(layers)} layers active"


def dropped(before: List[Layer], after: List[Layer]) -> List[Layer]:
    """Layers that were up and are not any more.

    WHY A HEARTBEAT AT ALL. The coverage report prints once, at launch. If the
    mount crashes an hour into a session - or someone runs `demo_cli unmount`
    in another window, or the egress proxy dies - nothing says so, and the
    person keeps working while believing they are covered. That is the SIXTH
    appearance of "is this thing actually protecting me?" in this project, and
    the one place it had no answer.

    Only TRANSITIONS are reported, never the current state. A guard that
    prints its status every minute is noise, and noise is how a real warning
    gets missed.
    """
    was_ok = {x.name for x in before if x.ok}
    return [x for x in after if not x.ok and x.name in was_ok]


def recovered(before: List[Layer], after: List[Layer]) -> List[Layer]:
    """The other direction: a layer that came back. Worth saying, because it
    tells the user the earlier warning no longer applies - otherwise they act
    on stale information for the rest of the session."""
    was_down = {x.name for x in before if not x.ok}
    return [x for x in after if x.ok and x.name in was_down]
