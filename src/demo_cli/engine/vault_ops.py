"""What the HashiCorp Vault CLI changes (M2.2f).

A secret, a policy, a mount, an auth method or a token lives in Vault, not in
the project: `reach(label, kind)` and policy.py decides. Labels:
`secret:vault@<address>` -> secret_write (ask), as the old rule gave every
vault write / delete; a token or lease revoked -> `cred:vault@<address>` ->
credential_rotation (ask).

The kind comes from the command (the longest known run of command words):
  DELETE     delete, kv delete / destroy / metadata delete, policy delete,
             secrets / auth / audit disable, namespace delete, plugin
             deregister, operator raft remove-peer, lease / token revoke
  OVERWRITE  write, patch, kv put / patch / rollback / undelete /
             enable-versioning / metadata put / patch, policy write, secrets
             enable / move / tune, auth enable / move / tune, audit enable,
             namespace create / patch / lock / unlock, plugin register /
             reload, operator init / rekey / rotate / generate-root / migrate
             / raft join / raft snapshot restore / raft autopilot set-config,
             unwrap (a wrapping token is single-use: unwrapping spends it)
  SERVICE_LOSS  operator seal, operator step-down
  SERVICE_KEEP  operator unseal
  reads      read, list, kv get / list / metadata get, status, version, ...
Not claimed (uncovered: today's path decides): servers and agents (server,
agent, proxy, monitor, debug, events), `ssh` (a remote shell), `login` (writes
a local token helper), `policy fmt` and `operator raft snapshot save` (local
files), pki / transit / transform imports and issuing, and every command the
CLI's own table does not list.

VERIFIED (2026-10-08) from Vault's own source (hashicorp/vault, main, release
v2.1.2): the command table is command/commands.go (GENERATED into
vault_data.py); options are parsed by Go's `flag` package (command/base.go,
FlagSets.Parse): `-x` and `--x` are the same option, `-x=v` or `-x v`, and
parsing STOPS at the first word that is not an option (later options are only
warned about); `-output-curl-string` and `-output-policy` print a curl command
or a policy instead of sending the request; `-address` names the server.
"""
from __future__ import annotations

from typing import List, Optional

from ..model import Word
from .effects import DELETE, OVERWRITE, SERVICE_KEEP, SERVICE_LOSS

_DELETE = frozenset({
    "delete", "kv delete", "kv destroy", "kv metadata delete", "policy delete",
    "secrets disable", "auth disable", "audit disable", "namespace delete",
    "plugin deregister", "plugin runtime deregister", "operator raft remove-peer"})
_REVOKE = frozenset({"lease revoke", "token revoke"})
_OVERWRITE = frozenset({
    "write", "patch", "kv put", "kv patch", "kv rollback", "kv undelete", "kv enable-versioning",
    "kv metadata put", "kv metadata patch", "policy write", "secrets enable", "secrets move",
    "secrets tune", "auth enable", "auth move", "auth tune", "audit enable", "namespace create",
    "namespace patch", "namespace lock", "namespace unlock", "plugin register", "plugin reload",
    "plugin runtime register", "operator init", "operator rekey", "operator rotate",
    "operator generate-root", "operator migrate", "operator raft join",
    "operator raft snapshot restore", "operator raft autopilot set-config", "unwrap"})
_LOSS = frozenset({"operator seal", "operator step-down"})
_KEEP = frozenset({"operator unseal"})
_READ = frozenset({
    "read", "list", "kv get", "kv list", "kv metadata get", "status", "version", "version-history",
    "path-help", "print", "print token", "policy read", "policy list", "secrets list", "auth list",
    "auth help", "audit list", "lease lookup", "lease renew", "namespace list", "namespace lookup",
    "token lookup", "token capabilities", "token renew", "plugin info", "plugin list",
    "plugin reload-status", "plugin runtime info", "plugin runtime list", "operator key-status",
    "operator usage", "operator utilization", "operator members", "operator diagnose",
    "operator raft list-peers", "operator raft autopilot get-config", "operator raft autopilot state",
    "operator raft snapshot inspect", "pki health-check", "pki list-intermediates",
    "pki verify-sign"})


def vault(w, inv, parsed, state, tool) -> None:
    from .vault_data import VAULT_COMMANDS
    args = list(inv.argv[1:])
    words: List[str] = []
    i = 0
    while i < len(args) and not args[i].expands and not args[i].value.startswith("-"):
        cand = " ".join(words + [args[i].value])
        if cand not in VAULT_COMMANDS:
            break
        words.append(args[i].value)
        i += 1
    if i < len(args) and args[i].expands and not words:
        w.impact.not_understood(inv.text, "a vault command named by an expansion")
        return
    cmd = " ".join(words)
    if not cmd:
        return w.impact.not_covered("vault")
    address: Optional[str] = None
    for k, a in enumerate(args[i:], start=i):
        if a.expands or not a.value.startswith("-"):
            break                                       # Go's flag: options end here
        name, eq, value = a.value.lstrip("-").partition("=")
        if name in ("h", "help", "output-curl-string", "output-policy"):
            return                                      # help, or print instead of sending
        if name == "address":
            address = value if eq else (args[k + 1].value if k + 1 < len(args) else None)
    where = address or "default"
    if cmd in _READ:
        return
    if cmd in _DELETE:
        return w.impact.reach(f"secret:vault@{where}", DELETE)
    if cmd in _REVOKE:
        return w.impact.reach(f"cred:vault@{where}", DELETE)
    if cmd in _OVERWRITE:
        return w.impact.reach(f"secret:vault@{where}", OVERWRITE)
    if cmd in _LOSS:
        return w.impact.reach(f"secret:vault@{where}", SERVICE_LOSS)
    if cmd in _KEEP:
        return w.impact.reach(f"secret:vault@{where}", SERVICE_KEEP)
    w.impact.not_covered(f"vault {cmd}")
