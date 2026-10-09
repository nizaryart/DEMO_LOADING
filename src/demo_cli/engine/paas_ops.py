"""What a PaaS CLI changes on the platform (M2.2b4b1): heroku, fly / flyctl,
vercel / vc, netlify, wrangler, firebase.

An app, a database or a deploy lives on the platform, not in the project:
`reach(label, kind)` and policy.py decides. Labels: `paas:` -> paas_destroy
(a whole app, site, database, volume or worker removed), `deploy:` ->
saas_deploy (a deploy, a config change, any other removal), `secret:` ->
secret_write.

RULINGS (Nizar, 2026-10-07): destroying an app / database / volume = DELETE on
paas_destroy (deny); a deploy, config or env change = OVERWRITE on saas_deploy
(ask); logs, status and lists read; creations stay with today's path.

WHAT IT CLAIMS, AND WHAT IT DOES NOT. The kind comes from the command's last
verb (DELETE: destroy delete remove rm reset purge drop wipe truncate prune;
OVERWRITE: set unset update edit deploy rollback promote restore import
release push publish rename move transfer attach detach rotate enable disable
upgrade; reads: list ls info show get status logs ...). Not claimed: creations
(create add new init launch fork clone copy), runs and shells (run exec ssh
console invoke), lifecycle (stop start restart suspend resume scale - as
docker, ruling R5), and every command the tool's own data does not list
(plugins, extensions): today's path decides them. Local-by-default commands
(wrangler kv / r2 object / d1 data without --remote, netlify database) are
not the platform: uncovered.

VERIFIED (2026-10-07) from each tool's own data (paas_data.py, generated):
heroku 11.11.0 oclif manifest (argv[0] is the id, ':' separated); flyctl
0.4.114 --help tree read with no network (cobra; hidden destroy / open / move
/ regions / settings included); firebase-tools 15.32.1 (argv[0] matched
case-insensitively); netlify-cli 27.11.2 (a deploy is production only with
--prod / -p / --prod-if-unlocked and no --draft); wrangler 4.148.0 registry
(kv / r2 object / d1 data act locally unless --remote); vercel 62.7.0 (a
known command word wins over a path; `--prod` / `--target production` deploys
to production, anything else is a preview - a creation).
"""
from __future__ import annotations

from typing import List, Optional

from ..model import Word
from .cloud_ops import READ, _reach
from .effects import DELETE, OVERWRITE, RUN

_DELETE_V = frozenset({"destroy", "delete", "remove", "rm", "reset", "purge", "drop", "wipe",
                       "truncate", "prune"})
_OVERWRITE_V = frozenset({"set", "unset", "update", "edit", "deploy", "rollback", "promote",
                          "restore", "import", "release", "push", "publish", "rename", "move",
                          "transfer", "attach", "detach", "rotate", "enable", "disable",
                          "upgrade"})
_READ_V = frozenset({"list", "ls", "info", "show", "get", "status", "logs", "log", "view",
                     "open", "describe", "inspect", "whoami", "version", "help", "history",
                     "releases", "tail", "check", "doctor", "dashboard", "docs", "ping", "dig",
                     "search", "wait", "verify", "url", "diff", "outdated", "report", "regions",
                     "versions", "deployments"})
# The object a removal takes away whole (ruling: paas_destroy).
_WHOLE = frozenset({"apps", "app", "sites", "site", "projects", "project", "databases",
                    "database", "db", "pg", "postgres", "mpg", "redis", "volumes", "volume",
                    "buckets", "bucket", "namespace", "namespaces", "backends", "machine",
                    "machines"})
_SECRET = frozenset({"secrets", "secret", "env", "config"})


def _verb_kind(path: List[str]) -> Optional[str]:
    v = path[-1]
    if v in _DELETE_V:
        return DELETE
    if v in _OVERWRITE_V:
        return OVERWRITE
    if v in _READ_V:
        return READ
    return None


def _label(tool: str, path: List[str], kind: str) -> str:
    objs = set(path[:-1]) or {path[-1]}
    if kind == DELETE and (objs & _WHOLE or path == ["destroy"] or path == ["delete"]):
        return f"paas:{tool}"
    if objs & {"secrets", "secret"}:
        return f"secret:{tool}"
    return f"deploy:{tool}"


def _claim(w, inv, tool: str, path: List[str], words: List[Word]) -> None:
    kind = _verb_kind(path)
    if kind is None:
        return w.impact.not_covered(f"{tool} {' '.join(path)}")
    if kind == READ:
        return
    _reach(w, inv, _label(tool, path, kind), kind, [], tool)


def _flag(words: List[Word], *names: str) -> bool:
    return any(not a.expands and (a.value in names or a.value.split("=", 1)[0] in names) for a in words)


# ---------------------------------------------------------------- heroku / firebase / netlify (argv[0] is the id)

def heroku(w, inv, parsed, state, tool) -> None:
    from .paas_data import HEROKU, HEROKU_ALIASES
    args = list(inv.argv[1:])
    if not args or args[0].expands or args[0].value.startswith("-"):
        return w.impact.not_covered("heroku")
    cid = HEROKU_ALIASES.get(args[0].value, args[0].value)
    if cid not in HEROKU:
        return w.impact.not_covered(f"heroku {args[0].value}")      # a plugin, or not heroku's
    if cid.split(":")[0] == "run" and not _flag(args[1:], "-h", "--help"):
        # M2.3b (Rb4): a command on a one-off dyno, with the app's environment.
        return _reach(w, inv, "deploy:heroku", RUN, [], tool)
    if _flag(args[1:], "-h", "--help"):
        return
    _claim(w, inv, "heroku", cid.split(":"), args[1:])


def firebase(w, inv, parsed, state, tool) -> None:
    from .paas_data import FIREBASE
    args = list(inv.argv[1:])
    i = 0
    while i < len(args) and not args[i].expands and args[i].value.startswith("-"):
        v = args[i].value.split("=", 1)[0]
        i += 2 if v in ("-P", "--project", "--account", "--token", "-c", "--config") and "=" not in args[i].value else 1
    if i >= len(args) or args[i].expands:
        return w.impact.not_covered("firebase")
    cid = args[i].value.lower()                                        # VERIFIED: case-insensitive
    if cid not in FIREBASE:
        return w.impact.not_covered(f"firebase {args[i].value}")
    rest = args[i + 1:]
    if _flag(rest, "-h", "--help"):
        return
    _claim(w, inv, "firebase", cid.split(":"), rest)


def netlify(w, inv, parsed, state, tool) -> None:
    from .paas_data import NETLIFY, NETLIFY_ALIASES
    args = list(inv.argv[1:])
    if not args or args[0].expands or args[0].value.startswith("-"):
        return w.impact.not_covered("netlify")
    cid = NETLIFY_ALIASES.get(args[0].value, args[0].value)
    if cid not in NETLIFY or cid.startswith(("database", "db")):
        return w.impact.not_covered(f"netlify {args[0].value}")       # database: the LOCAL dev db
    rest = args[1:]
    if _flag(rest, "-h", "--help"):
        return
    if cid == "deploy":
        prod = _flag(rest, "--prod", "-p", "--prod-if-unlocked") and not _flag(rest, "--draft")
        if not prod:
            return w.impact.not_covered("netlify deploy (a draft)")  # a creation
        return _reach(w, inv, "deploy:netlify", OVERWRITE, [], tool)
    _claim(w, inv, "netlify", cid.split(":"), rest)


# ---------------------------------------------------------------- fly / wrangler (space-separated paths)

def _longest(args: List[Word], known, aliases) -> tuple:
    path: List[str] = []
    best, at = None, 0
    for i, a in enumerate(args):
        if a.expands or a.value.startswith("-"):
            break
        cand = " ".join(path + [a.value])
        cand = aliases.get(cand, cand)
        if cand not in known:
            break
        path = cand.split()
        best, at = cand, i + 1
    return best, at


def fly(w, inv, parsed, state, tool) -> None:
    from .paas_data import FLY, FLY_ALIASES
    args = list(inv.argv[1:])
    known = {k: v for k, v in FLY.items() if k}
    cmd, at = _longest(args, known, FLY_ALIASES)
    if cmd is None:
        return w.impact.not_covered(f"fly {args[0].value if args else ''}".strip())
    if known[cmd][2]:                                                  # a group, not a command
        return w.impact.not_covered(f"fly {cmd}")
    rest = args[at:]
    if _flag(rest, "-h", "--help"):
        return
    if cmd == "deploy" and _flag(rest, "--build-only"):
        return
    _claim(w, inv, "fly", cmd.split(), rest)


_WRANGLER_LOCAL_READS = frozenset({"kv key list", "kv key get", "kv bulk get", "r2 object get",
                                   "complete"})


def wrangler(w, inv, parsed, state, tool) -> None:
    from .paas_data import WRANGLER_ALIASES, WRANGLER_COMMANDS, WRANGLER_LOCAL, WRANGLER_NAMESPACES
    args = list(inv.argv[1:])
    known = set(WRANGLER_COMMANDS) | set(WRANGLER_NAMESPACES)
    cmd, at = _longest(args, known, WRANGLER_ALIASES)
    if cmd is None and args and not args[0].expands and not args[0].value.startswith("-"):
        # M2.3b: no wrangler 4 command or namespace (`kv:key` is wrangler 3's
        # remote KV syntax): a remote change nobody read.
        return w.impact.not_understood(inv.text, f"wrangler {args[0].value}: not a command "
                                                 f"of the wrangler this engine knows")
    if cmd is None or cmd not in WRANGLER_COMMANDS:
        return w.impact.not_covered(f"wrangler {args[0].value if args else ''}".strip())
    rest = args[at:]
    if _flag(rest, "-h", "--help"):
        return
    remote = _flag(rest, "--remote", "--preview") or _flag(rest, "--local=false")
    if cmd in _WRANGLER_LOCAL_READS:
        return
    if cmd == "d1 execute" or (cmd in WRANGLER_LOCAL and not remote):
        # M2.3b: SQL on a D1 database, or a write to wrangler's local state
        # (.wrangler, VERIFIED local by default) - nobody read what it changes.
        return w.impact.not_understood(inv.text, f"wrangler {cmd} changes data the engine does not read")
    if cmd in ("deploy", "versions deploy") and _flag(rest, "--dry-run"):
        return
    if cmd == "delete":
        return _reach(w, inv, "paas:wrangler", DELETE, [], tool)        # the Worker
    _claim(w, inv, "wrangler", cmd.split(), rest)


# ---------------------------------------------------------------- vercel / vc

_VERCEL_GLOBAL_VALUES = frozenset({"--cwd", "-A", "--local-config", "-Q", "--global-config",
                                   "-S", "--scope", "-t", "--token", "-T", "--team", "--api"})


def vercel(w, inv, parsed, state, tool) -> None:
    from .paas_data import VERCEL_TOP
    args = list(inv.argv[1:])
    words: List[Word] = []
    i = 0
    while i < len(args):
        a = args[i]
        if a.expands:
            return w.impact.not_covered("vercel")
        v = a.value
        if v.startswith("-"):
            i += 2 if v in _VERCEL_GLOBAL_VALUES else 1
            continue
        words.append(a)
        i += 1
    flags = list(inv.argv[1:])
    if _flag(flags, "-h", "--help", "-v", "--version"):
        return
    first = words[0].value if words else None
    cmd = VERCEL_TOP.get(first) if first else "deploy"
    if first and cmd is None:
        cmd = "deploy"                                # a path (or an extension): deploy decides
    if cmd == "deploy":
        prod = _flag(flags, "--prod") or any(
            a.value in ("--target=production",) for a in flags) or any(
            flags[k].value == "--target" and k + 1 < len(flags) and flags[k + 1].value == "production"
            for k in range(len(flags)))
        if not prod:
            return w.impact.not_covered("vercel deploy (a preview)")  # a creation
        return _reach(w, inv, "deploy:vercel", OVERWRITE, [], tool)
    sub = words[1].value if len(words) > 1 else None
    if cmd in ("rollback", "promote"):
        if sub == "status":
            return
        return _reach(w, inv, "deploy:vercel", OVERWRITE, [], tool)
    if cmd == "remove":
        return _reach(w, inv, "deploy:vercel", DELETE, [], tool)
    w.impact.not_covered(f"vercel {first}")


# ---------------------------------------------------------------- entry

_TOOLS = {"heroku": heroku, "fly": fly, "flyctl": fly, "vercel": vercel, "vc": vercel,
          "netlify": netlify, "wrangler": wrangler, "firebase": firebase}


def paas(w, inv, parsed, state, tool) -> None:
    _TOOLS[tool](w, inv, parsed, state, tool)
