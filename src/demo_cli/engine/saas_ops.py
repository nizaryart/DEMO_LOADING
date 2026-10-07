"""What a store, CMS, payment or migration CLI changes (M2.2b4b2): shopify,
wp (wp-cli), stripe, and the migration tools rails / rake, manage.py /
django-admin, alembic, prisma, knex, flyway, liquibase.

Labels: `deploy:` -> saas_deploy (a Shopify theme / app), `cms:` -> saas_cms
(a WordPress site), `payment:` -> external_payment (money moved), `http:` ->
http_api_write (any other Stripe API write), `migration:` -> schema_migration.

RULINGS (Nizar, 2026-10-07): migrations upgrade / migrate = OVERWRITE,
downgrade / rollback / reset / drop / clean / flush = DELETE (schema_migration,
ask); reads and offline / SQL-printing modes read. Stripe: an operation that
moves money (charges, refunds, payouts, transfers, top-ups, payment intents,
invoice pay, credit notes) = SEND on external_payment (deny); any other
Stripe write = OVERWRITE / DELETE on http_api_write (ask). Creations stay
with today's path.

Not claimed: runners in front of the tool (`python manage.py`, `bundle exec
rake`, `npx prisma` - M2.3), every command the tool's own data does not list,
wp-cli commands outside the verified list, raw `stripe get|post|delete` and
`stripe trigger`.

VERIFIED (2026-10-07), each from the tool's own data (saas_data.py, generated):
@shopify/cli 4.8.5 manifest (space- or colon-separated ids); wp-cli 2.12.0 +
db / search-replace / entity / extension commands (docblocks; global options
are --key=value only); stripe-cli 1.53.1 generated resources (each op's HTTP
method); activerecord 8.1.4 databases.rake (60 db tasks, `db:<task>:<dbname>`
variants); Django 6.1.2 (the subcommand is argv[1]); alembic 1.20.0
(argparse, `--sql` = offline); prisma 7.10.0 (the stable release; 8.0.0 is a
release candidate); knex 3.3.0; flyway 13.9.0 (several operations per line);
liquibase 5.0.4 (kebab-case and camelCase names, legacy names, `*Sql` print).
"""
from __future__ import annotations

import re
from typing import List, Optional

from ..model import Word
from .cloud_ops import READ, _reach
from .effects import DELETE, OVERWRITE, SEND
from .paas_ops import _DELETE_V, _OVERWRITE_V, _READ_V, _flag

_ORDER = (DELETE, SEND, OVERWRITE)


def _worst(kinds) -> Optional[str]:
    ks = [k for k in kinds if k in _ORDER]
    return min(ks, key=_ORDER.index) if ks else None


# ---------------------------------------------------------------- shopify

def shopify(w, inv, parsed, state, tool) -> None:
    from .saas_data import SHOPIFY, SHOPIFY_ALIASES
    args = list(inv.argv[1:])
    path: List[str] = []
    best, at = None, 0
    for i, a in enumerate(args):                     # VERIFIED: oclif, topic separator ' '
        if a.expands or a.value.startswith("-") or "=" in a.value:
            break
        cand = ":".join(path + a.value.split(":"))
        cand = SHOPIFY_ALIASES.get(cand, cand)
        if cand not in SHOPIFY and not any(k.startswith(cand + ":") for k in SHOPIFY):
            break
        path = cand.split(":")
        if cand in SHOPIFY:
            best, at = cand, i + 1
    if best is None:
        return w.impact.not_covered("shopify")
    if _flag(args[at:], "-h", "--help"):
        return
    verb = best.split(":")[-1]
    kind = DELETE if verb in _DELETE_V else OVERWRITE if verb in _OVERWRITE_V | {"deploy", "push", "publish", "release"} \
        else READ if verb in _READ_V | {"pull", "info", "check"} else None
    if kind is None:
        return w.impact.not_covered(f"shopify {best.replace(':', ' ')}")
    if kind != READ:
        _reach(w, inv, "deploy:shopify", kind, [], tool)


# ---------------------------------------------------------------- wp (wp-cli)

_WP = {("db", "drop"): DELETE, ("db", "reset"): DELETE, ("db", "clean"): DELETE,
       ("db", "import"): OVERWRITE, ("site", "empty"): DELETE,
       ("option", "update"): OVERWRITE, ("option", "set"): OVERWRITE,
       ("plugin", "delete"): DELETE, ("plugin", "uninstall"): DELETE,
       ("theme", "delete"): DELETE, ("theme", "uninstall"): DELETE,
       ("plugin", "update"): OVERWRITE, ("plugin", "upgrade"): OVERWRITE,
       ("theme", "update"): OVERWRITE, ("theme", "upgrade"): OVERWRITE}
_WP_DELETE = frozenset({"post", "user", "comment", "term", "menu", "option", "site"})
_WP_UPDATE = frozenset({"post", "user", "comment", "term"})


def wp(w, inv, parsed, state, tool) -> None:
    args = list(inv.argv[1:])
    words, opts = [], []
    for a in args:
        if a.expands:
            return w.impact.not_covered("wp")
        (opts if a.value.startswith("--") else words).append(a.value)
    if any(o.startswith(("--exec", "--require")) for o in opts):
        w.impact.not_understood(inv.text, "wp-cli runs PHP code the engine cannot read (--exec / --require)")
        return
    if "--help" in opts or not words:
        return w.impact.not_covered("wp")
    cmd = tuple(words[:2])
    if words[0] == "search-replace":
        if "--dry-run" in opts:
            return
        return _reach(w, inv, "cms:wp", OVERWRITE, [], tool)
    kind = _WP.get(cmd)
    if kind is None and len(cmd) == 2 and cmd[1] == "delete" and cmd[0] in _WP_DELETE:
        kind = DELETE
    if kind is None and len(cmd) == 2 and cmd[1] == "update" and cmd[0] in _WP_UPDATE:
        kind = OVERWRITE
    if kind is None:
        return w.impact.not_covered(f"wp {' '.join(cmd)}")
    _reach(w, inv, "cms:wp", kind, [], tool)


# ---------------------------------------------------------------- stripe

_MONEY_RES = frozenset({"charges", "refunds", "payouts", "transfers", "topups", "credit_notes",
                        "transfer_reversals", "application_fees"})
_MONEY_OPS = {"payment_intents": {"create", "confirm", "capture", "increment_authorization"},
              "invoices": {"pay"}, "setup_intents": set(), "subscriptions": set()}


def stripe(w, inv, parsed, state, tool) -> None:
    from .saas_data import STRIPE
    args = [a for a in inv.argv[1:]]
    words: List[str] = []
    for a in args:
        if a.expands:
            return w.impact.not_covered("stripe")
        if a.value.startswith("-"):
            break
        words.append(a.value)
    key = next((" ".join(words[:n]) for n in range(len(words), 1, -1)
                if " ".join(words[:n]) in STRIPE), None)      # the longest "<...> <res> <op>"
    if key is None:
        return w.impact.not_covered(f"stripe {' '.join(words[:2])}".strip())
    if _flag(args, "-h", "--help"):
        return
    method = STRIPE[key]
    if method == "GET":
        return
    parts = key.split()
    res, op = parts[-2], parts[-1]
    if method == "POST" and (res in _MONEY_RES or op in _MONEY_OPS.get(res, ())):
        return _reach(w, inv, "payment:stripe", SEND, [], tool)
    _reach(w, inv, "http:api.stripe.com", DELETE if method == "DELETE" else OVERWRITE, [], tool)


# ---------------------------------------------------------------- rails / rake

_RAILS_DELETE = frozenset({"drop", "drop:all", "purge", "purge:all", "reset", "reset:all",
                           "truncate_all", "schema:load", "migrate:reset", "rollback",
                           "migrate:down", "migrate:redo", "seed:replant"})
_RAILS_OVERWRITE = frozenset({"migrate", "migrate:up", "seed", "fixtures:load", "prepare",
                              "setup", "setup:all", "environment:set"})
_RAILS_READ = frozenset({"version", "migrate:status", "abort_if_pending_migrations", "charset",
                         "collation", "load_config", "check_protected_environments", "environment",
                         "fixtures:identify", "forward"})


def rails(w, inv, parsed, state, tool) -> None:
    kinds, saw = [], False
    for a in inv.argv[1:]:
        if a.expands:
            return w.impact.not_covered(tool)
        v = a.value
        if not v.startswith("db:"):
            if v.startswith("-") or "=" in v:          # options, VAR=value arguments
                continue
            return w.impact.not_covered(f"{tool} {v}")  # another task / command: today's path
        saw = True
        task = v[3:]
        base = task if task in _RAILS_DELETE | _RAILS_OVERWRITE | _RAILS_READ else task.rsplit(":", 1)[0]
        if base in _RAILS_DELETE:
            kinds.append(DELETE)
        elif base in _RAILS_OVERWRITE:
            kinds.append(OVERWRITE)
        elif base in _RAILS_READ:
            kinds.append(READ)
        else:
            return w.impact.not_covered(f"{tool} {v}")
    if not saw:
        return w.impact.not_covered(tool)
    k = _worst(kinds)
    if k:
        _reach(w, inv, "migration:rails", k, [], tool)


# ---------------------------------------------------------------- manage.py / django-admin

_DJ = {"migrate": OVERWRITE, "flush": DELETE, "loaddata": OVERWRITE,
       "showmigrations": READ, "sqlmigrate": READ, "sqlflush": READ, "check": READ,
       "inspectdb": READ, "diffsettings": READ, "sqlsequencereset": READ}


def django(w, inv, parsed, state, tool) -> None:
    args = list(inv.argv[1:])
    if not args or args[0].expands:
        return w.impact.not_covered(tool)
    cmd, rest = args[0].value, args[1:]               # VERIFIED: the subcommand is argv[1]
    kind = _DJ.get(cmd)
    if kind is None:
        return w.impact.not_covered(f"{tool} {cmd}")
    if _flag(rest, "-h", "--help") or kind == READ:
        return
    if cmd == "migrate":
        if _flag(rest, "--plan", "--check"):
            return
        positional = [a for a in rest if not a.value.startswith("-")]
        if len(positional) >= 2:
            kind = DELETE                             # a target migration: it may go backward
    _reach(w, inv, "migration:django", kind, [], tool)


# ---------------------------------------------------------------- alembic

_ALEMBIC_VALUES = ("-c", "--config", "-n", "--name", "-x")


def alembic(w, inv, parsed, state, tool) -> None:
    args = list(inv.argv[1:])
    i = 0
    while i < len(args) and not args[i].expands and args[i].value.startswith("-"):
        v = args[i].value
        name = v.split("=", 1)[0]
        full = [o for o in ("--config", "--name", "--raiseerr", "--quiet", "--version") if o.startswith(name)] \
            if name.startswith("--") else [name]
        if name in ("--version", "-h", "--help"):
            return
        if name in _ALEMBIC_VALUES or (len(full) == 1 and full[0] in ("--config", "--name")):
            i += 1 if "=" in v else 2
            continue
        i += 1
    if i >= len(args) or args[i].expands:
        return w.impact.not_covered("alembic")
    cmd, rest = args[i].value, args[i + 1:]
    if _flag(rest, "-h", "--help", "--sql"):
        return                                        # VERIFIED: --sql is offline
    kind = {"upgrade": OVERWRITE, "downgrade": DELETE, "stamp": OVERWRITE}.get(cmd)
    if kind is None:
        if cmd in ("current", "history", "heads", "branches", "show", "check", "list_templates"):
            return
        return w.impact.not_covered(f"alembic {cmd}")
    _reach(w, inv, "migration:alembic", kind, [], tool)


# ---------------------------------------------------------------- prisma (7.10.0)

def prisma(w, inv, parsed, state, tool) -> None:
    words = [a.value for a in inv.argv[1:] if not a.value.startswith("-")]
    rest = list(inv.argv[1:])
    if any(a.expands for a in inv.argv[1:3]) or len(words) < 2:
        return w.impact.not_covered("prisma")
    group, sub = words[0], words[1]
    if _flag(rest, "-h", "--help"):
        return
    if group == "migrate":
        if sub in ("status", "diff"):
            return
        if sub == "reset":
            return _reach(w, inv, "migration:prisma", DELETE, [], tool)
        if sub == "dev" and _flag(rest, "--create-only"):
            return w.impact.not_covered("prisma migrate dev --create-only")   # a local file
        if sub in ("dev", "deploy", "resolve"):
            return _reach(w, inv, "migration:prisma", OVERWRITE, [], tool)
    if group == "db":
        if sub == "push":
            k = DELETE if _flag(rest, "--force-reset", "--accept-data-loss") else OVERWRITE
            return _reach(w, inv, "migration:prisma", k, [], tool)
        if sub == "seed":
            return _reach(w, inv, "migration:prisma", OVERWRITE, [], tool)
        if sub == "execute":
            w.impact.not_understood(inv.text, "the SQL prisma db execute reads from a file or stdin")
            return
    w.impact.not_covered(f"prisma {group} {sub}")


# ---------------------------------------------------------------- knex

_KNEX = {"migrate:latest": OVERWRITE, "migrate:up": OVERWRITE, "migrate:down": DELETE,
         "migrate:rollback": DELETE, "migrate:to": DELETE, "migrate:before": DELETE,
         "migrate:unlock": OVERWRITE, "seed:run": OVERWRITE,
         "migrate:list": READ, "migrate:currentVersion": READ}


def knex(w, inv, parsed, state, tool) -> None:
    cmd = next((a for a in inv.argv[1:] if not a.value.startswith("-")), None)
    if cmd is None or cmd.expands:
        return w.impact.not_covered("knex")
    kind = _KNEX.get(cmd.value)
    if kind is None:
        return w.impact.not_covered(f"knex {cmd.value}")
    if kind != READ and not _flag(list(inv.argv[1:]), "-h", "--help"):
        _reach(w, inv, "migration:knex", kind, [], tool)


# ---------------------------------------------------------------- flyway / liquibase

_FLYWAY = {"migrate": OVERWRITE, "clean": DELETE, "undo": DELETE, "baseline": OVERWRITE,
           "repair": OVERWRITE, "info": READ, "validate": READ}


def flyway(w, inv, parsed, state, tool) -> None:
    kinds = []
    for a in inv.argv[1:]:
        if a.expands:
            return w.impact.not_covered("flyway")
        v = a.value
        if v in ("-v", "--version", "-?", "-h", "--help"):
            return
        if v.startswith("-"):
            continue                                  # -key=value
        if v not in _FLYWAY:
            return w.impact.not_covered(f"flyway {v}")  # an extension's operation
        kinds.append(_FLYWAY[v])
    k = _worst(kinds)
    if k:
        _reach(w, inv, "migration:flyway", k, [], tool)


_LQ_DELETE = frozenset({"dropAll", "rollback", "rollbackCount", "rollbackToDate", "executeSql"})
_LQ_READ = frozenset({"status", "history", "validate", "diff", "snapshot", "listLocks",
                      "tagExists", "unexpectedChangesets", "calculateChecksum"})
_LQ_OVERWRITE = frozenset({"update", "updateCount", "updateToTag", "updateTestingRollback",
                           "changelogSync", "changelogSyncToTag", "clearChecksums",
                           "markNextChangesetRan", "releaseLocks", "tag"})


def liquibase(w, inv, parsed, state, tool) -> None:
    from .saas_data import LIQUIBASE
    args = list(inv.argv[1:])
    found = None
    for k, a in enumerate(args):
        if a.expands:
            return w.impact.not_covered("liquibase")
        v = a.value
        if v.startswith("-") or (k and args[k - 1].value.startswith("--") and "=" not in args[k - 1].value):
            continue                                  # an option, or its value
        found = LIQUIBASE.get(v)
        if found is None:
            return w.impact.not_covered(f"liquibase {v}")
        break
    if found is None or _flag(args, "-h", "--help"):
        return
    if found.endswith("Sql") or found in _LQ_READ:
        return                                        # VERIFIED: *Sql only prints the SQL
    if found not in _LQ_DELETE | _LQ_OVERWRITE:
        return w.impact.not_covered(f"liquibase {found}")
    _reach(w, inv, "migration:liquibase", DELETE if found in _LQ_DELETE else OVERWRITE, [], tool)


# ---------------------------------------------------------------- entry

_TOOLS = {"shopify": shopify, "wp": wp, "stripe": stripe, "rails": rails, "rake": rails,
          "manage.py": django, "django-admin": django, "alembic": alembic, "prisma": prisma,
          "knex": knex, "flyway": flyway, "liquibase": liquibase}


def saas(w, inv, parsed, state, tool) -> None:
    _TOOLS[tool](w, inv, parsed, state, tool)
