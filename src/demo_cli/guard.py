"""The Guard: the out-of-band reference monitor that ties the pieces together.

Flow for one command:

    classify -> resolve target (no default) -> build context (declared-first)
    -> compare declared intent to context -> snapshot the real target
    -> preview affected rows -> verify structural approval -> decide
    -> append a hash-chained receipt

Two modes:
    shadow   observe only - evaluate, snapshot, and record, but never block.
             The recommended way to adopt: prove value with zero workflow risk.
    enforce  gate - a blocking disposition prevents the action from proceeding.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional, Tuple

import contextlib
import functools
import os
import re
import shutil
import sys

from . import approval, checkpoint, preview as preview_mod, recovery
from .classify import (POSIX, POWERSHELL, Classification, classify_pipeline,
                       effective_segments, is_sql_preview_candidate)
from .config import Config, config_error_message, control_plane_paths, load_config
from .context import Context, Intent, build_context, compare_intent
from .decide import (ALLOW, ASK, BLOCKING, CONTEXT_MISMATCH, DRY_RUN, ESCALATE,
                     REVERSIBLE, Decision, decide)
from .receipts import Receipt, append_receipt


@functools.lru_cache(maxsize=32)
def _launcher(project_root: Optional[str | os.PathLike] = None) -> str:
    w = shutil.which("demo_cli")
    fallback = f"{sys.executable} -m demo_cli"
    if not w:
        return fallback
    cand = os.path.abspath(w)
    root = os.path.abspath(os.fspath(project_root)) if project_root else None
    if root is None:
        try:
            cfg = load_config()
            if cfg and cfg.project_root:
                root = os.path.abspath(cfg.project_root)
        except Exception:
            pass
    if root and recovery.within_project(cand, root):
        return fallback
    return cand


def _record_receipt(path: str, receipt: Receipt) -> bool:
    """Append a receipt without ever raising. The receipt is evidence, not a
    precondition for a decision - and the adapters fail open on an exception,
    so a failed write here would let the command run unguarded."""
    try:
        append_receipt(path, receipt)
        return True
    except Exception as exc:
        sys.stderr.write(f"demo_cli: receipt not written ({exc}); "
                         "the decision below still stands\n")
        return False


# PowerShell rules whose target is created rather than destroyed when the path
# is absent. Clear-Content is NOT here: it errors on a missing file rather than
# creating one, so there is nothing to reinterpret.
_CREATES_IF_MISSING = {"ps_set_content", "ps_new_item_force",
                       "ps_move_force", "ps_copy_force", "ps_rename_force"}


def _nothing_else_acts(c: Classification) -> bool:
    """Is the matched rule the ONLY reason this command was flagged?

    The two creates-nothing corrections below clear is_destructive,
    is_mutating AND matched_rule on the whole Classification. But
    classify_pipeline sets matched_rule from the FIRST matching segment, so a
    harmless new-file redirect in segment one erased every destructive
    finding after it:

        echo hi > new.txt && rm -rf src        -> ALLOW, receipt "safe"
        echo hi > new.txt; rm src/main.py      -> ALLOW, receipt "safe"
        echo hi > new.txt && git reset --hard  -> ALLOW, receipt "safe"
        rm -rf src && echo hi > new.txt        -> ESCALATE  (order flipped)
        echo hi > existing.txt && rm -rf src   -> ESCALATE  (target exists)

    A correction about ONE segment must not speak for the others. Each clause
    here is a separate way a later segment can act: a second destructive
    rule, a non-recoverable surface (`docker volume rm`, which is not a
    destructive SEGMENT and so escapes the count), a SQL mutation, an
    in-place file writer, or opaque remote execution.
    """
    return (c.destructive_segments <= 1
            and c.nonrecoverable_surface is None
            and not c.is_sql_mutating
            and not c.is_file_writer
            and not c.remote_exec)


# --------------------------------------------------------------------------
# DEMO_CLI'S OWN FILES - the control plane (Part A1, 2026-09-27)
#
# Measured in enforce mode before this: `echo > .demo_cli.toml`, an Edit of
# .claude/settings.json, `rm .demo_cli/receipts.jsonl` all came back
# REVERSIBLE and ran, and `rm -rf .demo_cli` was REVERSIBLE with its recovery
# point stored inside the folder it deleted. An agent that can change these
# files can switch the guard off, so any change to them is refused, whatever
# the rest of the command is - captured or not, it is not the agent's to make.
# --------------------------------------------------------------------------

_related = recovery._related


_SPAWNS = "runs inline code that starts other programs"


def _needs_the_net(command: str) -> Optional[str]:
    """Rb2 (M2.3b): a runner that may ALLOW with a note when no net exists,
    unless a policy row says otherwise: inline code naming a call that starts
    other programs (policy.INLINE_SPAWNS), or a package install, which runs the
    packages' own scripts (policy.PACKAGE_INSTALLS). The reason, or None."""
    from . import policy
    from .classify import _WRAPPERS
    from .model import parse
    try:
        cmds = parse(command.replace("\r\n", "\n")).commands
    except Exception:
        return None
    for cm in cmds:
        words = [w.value for w in cm.argv if not w.expands]
        while words and words[0] in _WRAPPERS:
            words = words[1:]
        if not words:
            continue
        tool, rest = os.path.basename(words[0]), words[1:]
        if tool in ("python", "python3", "py") and rest[:2] == ["-m", "pip"]:
            tool, rest = "pip", rest[2:]
        flags = policy.INLINE_SPAWNS.get(tool)
        if flags:
            opts, calls = flags
            for k, w in enumerate(rest[:-1]):
                if w in opts and any(call in rest[k + 1] for call in calls):
                    return _SPAWNS
        sub = next((w for w in rest if not w.startswith("-")), "")
        if (tool, sub) in policy.PACKAGE_INSTALLS:
            return "installs packages, which run their own install scripts"
    return None


_SQL_CLIENTS = frozenset({"sqlite3", "psql", "mysql", "mariadb"})


def _remote_family(tool: str) -> bool:
    """A tool of the engine's remote families (cloud, clusters, containers,
    data stores, services, accounts, SaaS, mail, ssh: rules.LAZY_FAMILIES, and
    the CLIs in rules.UNMODELLED_REMOTE). Runners are not - their code is local
    (M1); git and the SQL clients have their own exclusions (git_unread /
    sql_unread): a checkpoint holds .git and a project's sqlite file."""
    from . import policy
    from .engine.rules import LAZY_FAMILIES, UNMODELLED_REMOTE
    return ((tool in LAZY_FAMILIES or tool in UNMODELLED_REMOTE)
            and tool not in policy.CODE_RUNNERS and tool != "git" and tool not in _SQL_CLIENTS)


def _unparsed_remote(impact) -> bool:
    """M2.3b: a remote tool met an option its table does not know - its
    marker says `(option)`. The line was not read, so it is not understood:
    `gcloud --foo compute instances delete vm1` is not "no effect"."""
    return any(u.endswith("(option)") and _remote_family(u.split()[0]) for u in impact.uncovered)


def _net_blind(impact, command: str) -> Optional[str]:
    """Does this unread line reach past local files, where neither the net nor
    a checkpoint sees (V18)? Yes when an unread part is a call to a tool of
    the engine's remote families (cloud, clusters, containers, data stores,
    services, accounts, SaaS, mail, ssh: engine/rules.LAZY_FAMILIES, runners
    excepted - their code is local, M1), when such a tool or a download
    shares the line with what cannot be read (`aws s3 cp s3://b/x.sh - |
    bash`), or when a runner reads a download (`bash <(curl ...)`).
    policy.LOCAL_UNREAD lists the remote-family calls that only touch files.
    Returns "fetch" for fetched code that runs (fetch-and-run: its deny
    channel), "remote" for any other unread remote call, None otherwise."""
    from . import policy
    from .classify import _WRAPPERS
    from .engine.rules import LAZY_FAMILIES
    from .model import parse

    def calls(text, depth=0):
        """Every command the text runs, $( ) and backticks included."""
        try:
            cmds = parse(text.replace("\r\n", "\n")).commands
        except Exception:
            return
        for cm in cmds:
            words = [w.value for w in cm.argv if not w.expands]
            while words and words[0] in _WRAPPERS:
                words = words[1:]
            if words:
                yield os.path.basename(words[0]), (words[1] if len(words) > 1 else "")
            if depth < 4:
                for w in cm.argv:
                    for _a, _b, inner in w.subs:
                        yield from calls(inner, depth + 1)

    def substituted(text):
        """The commands inside $( ) / backticks: their output is part of the line."""
        try:
            cmds = parse(text.replace("\r\n", "\n")).commands
        except Exception:
            return
        for cm in cmds:
            for w in cm.argv:
                for _a, _b, inner in w.subs:
                    yield from calls(inner, 1)

    def remote(tool, sub):
        return (_remote_family(tool) and (tool, sub) not in policy.LOCAL_UNREAD) \
            or tool in policy.FETCHERS

    if re.search(r"<\([^)]*\b(?:%s)\b" % "|".join(sorted(policy.FETCHERS)), command):
        return "fetch"
    if any(t in policy.FETCHERS for t, _ in calls(command)):
        # Download, then run it: `curl -o x.sh URL && bash x.sh`.
        fetched = {os.path.normcase(p) for p in list(impact.created) + list(impact.creates)}
        try:
            cmds = parse(command.replace("\r\n", "\n")).commands
        except Exception:
            cmds = []
        for cm in cmds:
            words = [w.value for w in cm.argv if not w.expands]
            while words and words[0] in _WRAPPERS:
                words = words[1:]
            if words and (os.path.basename(words[0]) in policy.CODE_RUNNERS or "/" in words[0]):
                if any(os.path.normcase(os.path.abspath(x)) in fetched for x in words):
                    return "fetch"
    if _unparsed_remote(impact):
        return "remote"
    if not impact.unknown:
        return None
    on_line = [remote(t, sub) for t, sub in calls(command)]
    if any(why == "a shell runs whatever the pipe feeds it" for _u, why in impact.unknown) and any(on_line):
        return "fetch"                      # a download piped into a shell
    if any(t in policy.FETCHERS for t, _ in substituted(command)):
        return "fetch"                      # `eval "$(curl ...)"`: a download that runs
    if any(remote(t, sub) for unit, _why in impact.unknown for t, sub in calls(unit)):
        return "remote"
    return "remote" if any(on_line) else None


def _db_targets(impact) -> Tuple[List[recovery.Target], bool]:
    """Capture targets for the engine's capturable databases. ok=False when
    any of them has no literal URL to dump. SQLite is NOT here: a sqlite db
    is a file, already in impact.destroys."""
    targets, ok = [], True
    for label in sorted(impact.databases):
        url = impact.db_urls.get(label)
        if not url:
            ok = False
            continue
        targets.append(recovery.Target("postgres", url, label))
    return targets, ok


def _mount_covers_project(mountpoint: str, project_root: str) -> bool:
    """True if mountpoint is or contains project_root (case-insensitive on Windows)."""
    try:
        mp = os.path.normcase(os.path.abspath(mountpoint))
        pr = os.path.normcase(os.path.abspath(project_root))
        return mp == pr or os.path.commonpath([mp, pr]) == mp
    except (ValueError, Exception):
        return False


def _control_plane_hits(paths, cfg: Config) -> List[str]:
    """The paths among `paths` that are demo_cli's own files, lie inside
    them, or are a directory that holds them. Compared by path and by real
    path: a write through a link lands where the link points."""
    planes = control_plane_paths(cfg)
    real_planes = [os.path.realpath(q) for q in planes]
    root = os.path.abspath(cfg.project_root or os.getcwd())
    real_root = os.path.realpath(root)
    return [p for p in paths
            if p not in (root, real_root) and (
                any(_related(p, q) for q in planes)
                or any(_related(os.path.realpath(p), q) for q in real_planes)
            )]


def _shown(path: str, cfg: Config) -> str:
    root = os.path.abspath(cfg.project_root or os.getcwd())
    home = os.path.expanduser("~")
    if recovery._contains(root, path):
        return os.path.relpath(path, root)
    if recovery._contains(home, path):
        return os.path.join("~", os.path.relpath(path, home))
    return path


def _files_reason(hits: List[str], cfg: Config) -> str:
    names = ", ".join(_shown(p, cfg) for p in hits[:3])
    if len(hits) > 3:
        names += f", +{len(hits) - 3} more"
    return (f"This changes demo_cli's own files, or a directory holding them "
            f"({names}): its config, hook settings, ledger or recovery store. "
            f"An agent may not change them - they are what make demo_cli's "
            f"decisions trustworthy.")


# `demo_cli <subcommand>` that changes demo_cli's own state (Part A1b). The
# read-only ones - status, doctor, log, diff, verify, report, receipt(s),
# check - and undo stay allowed. Judged at the AGENT doors only: guard-shell
# is the human's `!` door and keeps skipping demo_cli's own invocations.
_STATE_CHANGING = frozenset({
    "init", "setup", "teardown", "_teardown-admin", "_register-task",
    "install-hook", "install-shell-guard", "protect", "unprotect",
    "mount", "unmount", "prune",
})
ENGINE_UNAVAILABLE = "engine_unavailable"
_PIP = re.compile(r"^pip(?:\d+(?:\.\d+)*)?$")


def _long_option(tok: str, option: str) -> bool:
    """argparse accepts any unambiguous prefix of a long option, so
    `--anch` is `--anchor`. Three characters is unambiguous for every
    option asked about here."""
    head = tok.split("=", 1)[0]
    return len(head) >= 3 and option.startswith(head)


def _agent_state_change(command: str, dialect: str) -> Optional[str]:
    """The demo_cli invocation or uninstall in `command` that changes
    demo_cli's own state, or None. Units are read raw AND with same-line
    variables substituted, so `DC=demo_cli; $DC teardown` is seen."""
    units = (effective_segments(command, dialect)
             + effective_segments(command, dialect, substitute=True))
    for seg, seg_dialect in units:
        toks = recovery._tokenize(seg, True if seg_dialect == POWERSHELL else None)
        if toks and toks[0] == "&":                  # PowerShell call operator
            toks = toks[1:]
        if not toks:
            continue
        word = toks[0].replace("\\", "/").rsplit("/", 1)[-1].lower()
        if word.endswith(".exe"):
            word = word[:-4]
        args = toks[1:]
        if word.startswith("python") or word == "py":
            if args[:2] == ["-m", "demo_cli"]:
                word, args = "demo_cli", args[2:]
            elif args[:2] == ["-m", "pip"]:
                word, args = "pip", args[2:]
        if word == "demo_cli" and args:
            sub, rest = args[0], args[1:]
            if sub in _STATE_CHANGING:
                return f"demo_cli {sub}"
            if sub in ("target", "targets") and "add" in rest:
                return f"demo_cli {sub} add"
            if sub == "egress":
                flag = next((t for t in rest if _long_option(t, "--trust-ca")
                             or _long_option(t, "--untrust-ca")), None)
                if flag:
                    return f"demo_cli egress {flag}"
            if sub == "verify" and any(_long_option(t, "--anchor") for t in rest):
                return "demo_cli verify --anchor"
        elif (word == "pipx" or _PIP.match(word)) and args[:1] == ["uninstall"]:
            names = {a.lower().replace("_", "-") for a in args[1:] if not a.startswith("-")}
            if "demo-cli" in names:
                return f"{word} uninstall demo_cli"
    return None


def _engine_predict(command: str, dialect: str, cfg: Config,
                    explicit_db: Optional[str] = None,
                    db_url: Optional[str] = None, guessed: bool = False):
    """Run the engine once - or, when the door only GUESSED the dialect, once
    per dialect with the two readings combined (PS8). Returns
    (prediction_dict, impact)."""
    if guessed and dialect == POWERSHELL:
        return _engine_predict_both(command, cfg, explicit_db, db_url)
    if os.environ.get("DEMO_CLI_SHADOW_ENGINE", "1").strip() == "0":
        return None, None
    import time
    t0 = time.perf_counter()
    if dialect not in (POSIX, POWERSHELL):
        out = {"engine": "shadow-1", "skipped": dialect}
        out["ms"] = round((time.perf_counter() - t0) * 1000, 2)
        return out, None
    retried = False
    try:
        from .engine import predict, _render, RETRY_BUDGET_MS
        from .engine.simulate import BudgetExceeded
        if cfg.project_root and recovery.within_project(os.getcwd(), cfg.project_root):
            cwd = os.path.abspath(os.getcwd())
        else:
            cwd = os.path.abspath(cfg.project_root or os.getcwd())
        try:
            pred = predict(command, cfg, cwd=cwd, explicit_db=explicit_db, db_url=db_url,
                           dialect=dialect)
        except BudgetExceeded:
            retried = True
            pred = predict(command, cfg, cwd=cwd, explicit_db=explicit_db, db_url=db_url,
                           budget_ms=RETRY_BUDGET_MS, dialect=dialect)
        out = _render(pred, cfg)
        if retried:
            out["retried"] = True
        out["ms"] = round((time.perf_counter() - t0) * 1000, 2)
        return out, pred.impact
    except Exception as exc:
        from .engine.simulate import BudgetExceeded
        why = "budget" if isinstance(exc, BudgetExceeded) else f"{type(exc).__name__}: {exc}"
        out = {"engine": "shadow-1", "error": why}
        if retried:
            out["retried"] = True
        out["ms"] = round((time.perf_counter() - t0) * 1000, 2)
        return out, None


def _engine_predict_both(command: str, cfg: Config, explicit_db: Optional[str],
                         db_url: Optional[str]):
    """PS8: read the line as PowerShell AND as POSIX and combine the two
    impacts (engine.combine_guessed). If one reading fails, the other stands
    alone; if both fail, the line goes where any engine failure goes."""
    import time
    from .engine import _render, combine_guessed
    from .engine.verdict import verdict
    t0 = time.perf_counter()
    ps_out, ps_imp = _engine_predict(command, POWERSHELL, cfg, explicit_db, db_url)
    px_out, px_imp = _engine_predict(command, POSIX, cfg, explicit_db, db_url)
    if ps_imp is None and px_imp is None:
        return ps_out, None
    if ps_imp is None or px_imp is None:
        out, imp = (px_out, px_imp) if ps_imp is None else (ps_out, ps_imp)
        out = dict(out)
        out["dialect"] = "guessed: only one reading succeeded"
        return out, imp
    imp = combine_guessed(ps_imp, px_imp)

    class _P:                                    # the shape _render expects
        pass
    p = _P()
    p.impact = imp
    p.decision, p.why = verdict(imp, cfg)
    out = _render(p, cfg)
    out["dialect"] = "guessed: read as PowerShell and as POSIX (PS8)"
    out["ms"] = round((time.perf_counter() - t0) * 1000, 2)
    return out, imp


def _shadow_prediction(command: str, dialect: str, cfg: Config,
                       explicit_db: Optional[str] = None,
                       db_url: Optional[str] = None) -> Optional[dict]:
    return _engine_predict(command, dialect, cfg, explicit_db, db_url)[0]


@dataclass
class GuardResult:
    command: str
    classification: Classification
    context: Context
    decision: Decision
    mode: str
    target: Optional[recovery.Target] = None
    recovery_entry: Optional[dict] = None
    preview_count: Optional[int] = None
    preview_rows: list = field(default_factory=list)
    preview_cols: list = field(default_factory=list)
    mismatches: List[Tuple[str, str, str]] = field(default_factory=list)
    affected_paths: List[str] = field(default_factory=list)
    receipt: Optional[Receipt] = None
    prediction: Optional[dict] = None       # the engine's reading (it decides what it reads)
    rewrite: Optional[str] = None           # command to run under behavioral supervisor
    group_id: Optional[str] = None
    decided_by: Optional[str] = None        # C3: see Receipt.decided_by

    @property
    def allowed(self) -> bool:
        """Whether the action may proceed unattended."""
        if self.mode == "shadow":
            return True
        return self.decision.decision not in BLOCKING and not self.decision.is_ask

    @property
    def permission(self) -> str:
        """Map the disposition to a Claude Code permissionDecision."""
        d = self.decision.decision
        if d in BLOCKING:
            return "deny"
        if d in ASK:
            return "ask"
        return "allow"


class AgentDirectoryUnreachable(RuntimeError):
    """The directory the agent said it was working in cannot be entered."""


@contextlib.contextmanager
def agent_directory(cwd: str):
    r"""Stand where the agent stands, for the duration of one evaluation.

    WHY THIS EXISTS. Every adapter reads `cwd` from the hook payload, uses it
    for load_config(start=cwd), and then lets paths resolve against the HOOK
    PROCESS's own directory. evaluate() takes no cwd; evaluate_file_edit()
    calls os.path.abspath(file_path) directly. Project P, agent working in
    P/sub, a file of the same name in both:

        decision       REVERSIBLE
        printed        "recovery point captured before this ran"
        snapshot held  the file at P
        agent deleted  the file in P/sub

    `undo` restores the bystander and the real work is gone. Commit 14dda64
    fixed that exact sentence for a `cd` INSIDE a command line - "a recovery
    point holding the wrong tree, reported REVERSIBLE" - and never questioned
    the process's own directory as a base that might already be wrong.

    LIVES HERE, NOT IN THE ADAPTERS, and wraps BOTH entry points. The first
    draft wrapped only the shell call, which left Edit / Write / MultiEdit /
    NotebookEdit resolving against the hook's directory - a partial fix that
    reads as complete, and the fifth time in this project a claim has landed
    in one of two places (design review, 2026-09-14).

    load_config MUST ALREADY HAVE RUN when this is entered. Config discovery
    walks up from `cwd` explicitly and stores absolute paths: project_root,
    recovery_dir and receipts_path are all os.path.join(project_root, ...),
    so neither ledger nor any snapshot destination moves in here. That
    ordering is load-bearing, not incidental.

    UNREACHABLE MEANS ESCALATE, NOT "CARRY ON HERE". chdir fails only when
    the directory is gone or unreadable - rare, and a state in which nobody
    can resolve a relative operand correctly. Falling back to our own
    directory would be "resolved is not the same as found" a third time:
    holding the information that the base is unreliable, and discarding it.

    A FAILED RESTORE IS LOUD. The hook is NOT always a one-shot process -
    cli.py calls run_pretooluse in-process inside doctor's self-test, itself
    already inside a chdir - so swallowing this would leave a surviving
    caller in the agent's directory, every later resolution wrong and nothing
    reporting it. That is the class being closed, recreated by its own fix.
    """
    previous = os.getcwd()
    try:
        os.chdir(cwd)
    except OSError as exc:
        raise AgentDirectoryUnreachable(str(cwd)) from exc
    try:
        yield
    finally:
        try:
            os.chdir(previous)
        except OSError as exc:                       # pragma: no cover
            raise RuntimeError(
                f"could not return to {previous} after evaluating in {cwd}: "
                f"{exc}. This process's working directory is now wrong for "
                f"everything that follows.") from None


class _Facts:
    __slots__ = ("target", "entry", "affected_paths", "snap_notes", "group_id",
                 "supervisable", "net_name", "rewrite", "checkpoint_skipped",
                 "checkpoint_taken", "remote_pg", "strategy", "c", "engine_error",
                 "remote_listed", "note")

    def __init__(self, target=None, entry=None, affected_paths=None, snap_notes=None,
                 group_id=None, supervisable=False, net_name=None, rewrite=None,
                 checkpoint_skipped=None, checkpoint_taken=False, remote_pg=False,
                 strategy="snapshot", c=None, engine_error=None, remote_listed=None, note=None):
        self.target = target; self.entry = entry; self.affected_paths = affected_paths or []
        self.snap_notes = snap_notes or {}; self.group_id = group_id
        self.supervisable = supervisable; self.net_name = net_name; self.rewrite = rewrite
        self.checkpoint_skipped = checkpoint_skipped; self.checkpoint_taken = checkpoint_taken
        self.remote_pg = remote_pg; self.strategy = strategy; self.c = c
        self.engine_error = engine_error
        self.remote_listed = remote_listed or []
        self.note = note                  # M2.3: what was NOT read, said to the person


class Guard:
    def __init__(self, config: Optional[Config] = None, mode: Optional[str] = None):
        self.config = config or load_config()
        # A config that cannot be read cannot tell us its mode either, and
        # falling back to the default (shadow) turned "every command is
        # blocked" into "nothing is blocked": the refusal was recorded and
        # printed, and every adapter let the command run - a config written
        # for enforce was silently observe-only (2026-09-27). Refusing needs
        # enforce. An explicit `mode` (`check --mode`) still wins.
        self.mode = mode or ("enforce" if self.config.config_error else self.config.mode)

    def _refuse_broken_config(self, command: str, agent_id: str,
                              session_id: str) -> GuardResult:
        """Block, loudly and actionably, when .demo_cli.toml cannot be read.

        A config that is MISSING means "no opinion" and falls back to defaults.
        A config that is PRESENT but unreadable means the user asked for
        protection we cannot deliver - so we refuse rather than proceed
        unguarded. This is fail-closed on the USER'S config, and it does not
        change the separate rule that our OWN bugs still fail open.
        """
        c = Classification(is_destructive=False, is_mutating=False,
                           matched_rule="config_unreadable", segments=[command])
        ctx = build_context(command, cwd=self.config.project_root)
        decision = Decision(
            ESCALATE,
            config_error_message(self.config),
            recoverable=False,
            next_steps=[
                f"Fix {self.config.source_path}",
                "or delete it to fall back to shadow mode (observe only)",
                "a UTF-8 BOM is the usual cause when PowerShell wrote the file",
            ],
        )
        receipt = Receipt(
            action_raw=command, action_type="config", target_environment=ctx.environment,
            decision=decision.decision, reason=decision.reason, mode=self.mode,
            matched_rule="config_unreadable", classification="safe",
            context=ctx.as_dict(), agent_id=agent_id, session_id=session_id,
        )
        _record_receipt(self.config.receipts_path, receipt)
        return GuardResult(command=command, classification=c, context=ctx,
                           decision=decision, mode=self.mode, receipt=receipt)

    def _refuse_control_plane(self, action_raw: str, c: Classification,
                              reason: str, next_steps: List[str],
                              intent: Intent, agent_id: str, session_id: str,
                              dialect: Optional[str],
                              prediction: Optional[dict] = None) -> GuardResult:
        """ESCALATE a change to demo_cli's own files or state. Nothing is
        captured: a recovery point would live in the very store being
        changed, and the change is not the agent's to make either way. The
        mode still applies - in shadow this is recorded, not enforced."""
        c.matched_rule = "control_plane"
        c.is_mutating = True
        ctx = build_context(action_raw, cwd=self.config.project_root)
        decision = Decision(ESCALATE, reason, recoverable=False, next_steps=next_steps)
        receipt = Receipt(
            action_raw=action_raw, action_type=c.action_type,
            target_environment=ctx.environment, decision=ESCALATE, reason=reason,
            mode=self.mode, matched_rule="control_plane",
            classification="destructive" if c.is_destructive else "mutating",
            context=ctx.as_dict(), declared_intent=intent.as_dict(),
            pipeline_segments=c.segments if c.is_pipeline else [],
            remote_exec=c.remote_exec, dialect=dialect,
            agent_id=agent_id, session_id=session_id, prediction=prediction,
        )
        _record_receipt(self.config.receipts_path, receipt)
        return GuardResult(command=action_raw, classification=c, context=ctx,
                           decision=decision, mode=self.mode, receipt=receipt,
                           prediction=prediction)

    def evaluate(self, command: str, target_path: Optional[str] = None,
                 explicit_db: Optional[str] = None, db_url: Optional[str] = None,
                 intent: Optional[Intent] = None, actual_env: Optional[str] = None,
                 approval_token: Optional[str] = None, agent_id: str = "unknown",
                 session_id: str = "unknown", dialect: str = POSIX,
                 door: Optional[str] = None, can_supervise: bool = False,
                 dialect_guessed: bool = False) -> GuardResult:
        """`dialect` says which shell wrote this text - POSIX or POWERSHELL.
        It decides how line continuations are folded, and the two spellings are
        not interchangeable (see classify.join_continuations). The adapters know
        it from the tool name; everything else keeps the POSIX default.

        `door` is "agent" from the agent hooks (Claude Code, Codex, Cursor).
        Only there is running a state-changing `demo_cli` subcommand refused:
        `check` and the `!` trap are the human's doors."""
        intent = intent or Intent(); command = command.strip()
        early = self._early_refusal(command, dialect, door, intent, agent_id, session_id)
        if early: return early
        c = classify_pipeline(command, dialect)
        prediction, impact = _engine_predict(command, dialect, self.config, explicit_db, db_url,
                                             guessed=dialect_guessed)
        refused = self._control_plane_refusal(command, dialect, door, c, impact, prediction, intent, agent_id, session_id)
        if refused: return refused
        route = None if self._engine_applies(dialect, impact) else self._unread_route(command, dialect, impact)
        reading = ("PowerShell and POSIX readings (dialect guessed)" if dialect_guessed
                   and dialect == POWERSHELL else
                   "PowerShell reading" if dialect == POWERSHELL else "POSIX reading")
        if self._engine_applies(dialect, impact):
            f = self._engine_facts(command, dialect, c, impact, target_path, explicit_db, db_url)
            decided_by = f"engine, {reading}"
        elif route is not None:
            f = self._unread_facts(route, command, dialect, c, impact, target_path, explicit_db,
                                   db_url, can_supervise, intent, actual_env)
            decided_by = f"engine, {reading}: not fully read ({route} route)"
        else:
            # B0's guard (an engine failure never becomes a silent ALLOW) now
            # covers PowerShell too: since C3 it is read by the same engine.
            engine_error = ((prediction or {}).get("error")
                            if dialect in (POSIX, POWERSHELL) and impact is None else None)
            f = self._legacy_facts(command, dialect, c, target_path, explicit_db, db_url, can_supervise, intent, actual_env, engine_error=engine_error)
            decided_by = "old text rules" + (" (the engine failed)" if engine_error else "")
        ctx, mismatches, approval_ok = self._context(command, f, intent, actual_env, approval_token)
        decision = self._decide(command, f, ctx, mismatches, approval_ok)
        return self._record(command, c, f, ctx, decision, intent, prediction, dialect, agent_id,
                            session_id, decided_by=decided_by)

    def _early_refusal(self, command: str, dialect: str, door: Optional[str],
                       intent: Intent, agent_id: str, session_id: str) -> Optional[GuardResult]:
        return self._refuse_broken_config(command, agent_id, session_id) if self.config.config_error else None

    def _control_plane_refusal(self, command: str, dialect: str, door: Optional[str],
                               c: Classification, impact, prediction, intent: Intent,
                               agent_id: str, session_id: str) -> Optional[GuardResult]:
        # DEMO_CLI'S OWN FILES AND STATE, before anything else. Before the
        # creation correction below on purpose: creating .demo_cli.toml or
        # .claude/settings.local.json is exactly as much a change to the
        # guard as editing one.
        if door == "agent":
            what = _agent_state_change(command, dialect)
            if what:
                verb = "uninstalls demo_cli" if " uninstall " in what else "changes demo_cli's own state"
                return self._refuse_control_plane(
                    command, c, f"This runs `{what}`, which {verb}. An agent may not do that.",
                    ["Run it yourself, outside the agent."],
                    intent, agent_id, session_id, dialect, prediction)
        written = {os.path.abspath(p) for p in recovery.written_paths(command, dialect)}
        if impact is not None:
            written |= set(impact.touched)       # the engine's paths are already absolute
        hits = _control_plane_hits(sorted(written), self.config)
        if hits:
            return self._refuse_control_plane(
                command, c, _files_reason(hits, self.config),
                ["Make this change yourself, outside the agent."],
                intent, agent_id, session_id, dialect, prediction)
        return None

    def _engine_applies(self, dialect: str, impact) -> bool:
        """C3: a line the engine reads FULLY is decided by the engine, in
        either dialect. There is no second opinion and no merge with the old
        text rules - one reading, one decider (the POSIX half of this is
        M2.3b; PowerShell joins it here)."""
        return (dialect in (POSIX, POWERSHELL) and impact is not None
                and not impact.uncovered and not impact.unknown)

    def _unread_route(self, command: str, dialect: str, impact) -> Optional[str]:
        """M2.3a (rulings M1-M5): which way a POSIX line the engine did not
        fully read goes, now that the old text rules no longer decide it.
        None = the old rules still do: a POSIX line that names a PowerShell
        or cmd.exe word (M5), or an engine that failed. A PowerShell line is
        routed like a POSIX one since C3 (ruling PS6).
          'unknown' - something on the line could not be read (M3)
          'runner'  - a program that runs code this engine does not read (M1)
          'plain'   - only words with no rule: they have no effect (the floor)"""
        from . import policy
        if dialect not in (POSIX, POWERSHELL) or impact is None:
            return None
        words = {u.split()[0] for u in impact.uncovered}
        if dialect == POSIX and words & policy.OLD_RULES_KEEP:
            # M5: a POSIX line that NAMES a PowerShell or cmd.exe word still
            # goes to the old text rules. A PowerShell line does not: C3 is
            # its reader now (ruling PS6), and deferring would have let
            # `cmd /c del a.txt` through, because no old rule flags a bare
            # `del` inside cmd.
            return None
        if impact.unknown or _unparsed_remote(impact):
            return "unknown"
        if words & policy.CODE_RUNNERS or words & self._started_by_path(command):
            return "runner"
        if any(w.lower().endswith(".ps1") for w in words):
            return "runner"          # a .ps1 from either shell: code we do not read
        return "plain"

    @staticmethod
    def _started_by_path(command: str) -> set:
        """Programs the line starts by a path (`./x.sh`, `bin/run`): code
        this engine does not read, whatever its name."""
        from .model import parse
        try:
            script = parse(command.replace("\r\n", "\n"))
        except Exception:
            return set()
        out = set()
        for cm in script.commands:
            if cm.argv and not cm.argv[0].expands and "/" in cm.argv[0].value:
                out.add(os.path.basename(cm.argv[0].value))
        return out

    def _unread_facts(self, route: str, command: str, dialect: str, c: Classification, impact,
                      target_path: Optional[str], explicit_db: Optional[str],
                      db_url: Optional[str], can_supervise: bool, intent: Intent,
                      actual_env: Optional[str]) -> _Facts:
        """M2.3a/b. What the engine DID read decides first: a remote change
        that escalates, a destroy outside the project, a database nothing can
        capture - an unread part cannot make those any better. A line whose
        unread part acts beyond local files escalates (_net_blind). Otherwise
        the unread part goes to the runtime net, else a checkpoint (never for
        a line with an operand outside the project: V17). With neither, a
        runner is ALLOWED with an honest note (M1) unless a policy row says it
        needs the net (Rb2), and an unread line ESCALATES (M3). Git and SQL
        lines never go to the net: it cannot capture .git or a database. The
        old text rules no longer decide a POSIX line here (M2.3b)."""
        from .engine.verdict import assess
        from .model import parse
        a = assess(impact, self.config)
        if route == "plain" or a.remote_escalated or a.outside or a.no_capture or a.plane_hits:
            return self._engine_facts(command, dialect, c, impact, target_path, explicit_db, db_url)
        try:
            tools = {os.path.basename(cm.argv[0].value) for cm in parse(command).commands
                     if cm.argv and not cm.argv[0].expands}
        except Exception:
            tools = set()
        segments = max(c.destructive_segments, 1)          # the classifier's count stays
        c.is_destructive = c.is_mutating = True
        c.is_sql_mutating = c.is_file_writer = c.remote_exec = False
        c.nonrecoverable_surface = None
        c.run_surfaces = []
        c.destructive_segments = segments
        blind = _net_blind(impact, command)
        if blind:
            # A cloud / container / service / SaaS ... call nobody read, or a
            # download feeding what runs: it acts where neither the net nor a
            # checkpoint sees (V18). It escalates.
            c.matched_rule = "remote_unread"
            c.remote_exec = blind == "fetch"               # fetch-and-run keeps its deny channel
            what = sorted({u for u in impact.uncovered} | {unit.split("\n")[0][:60] for unit, _w in impact.unknown})
            return _Facts(entry=None, c=c,
                          note=f"Part of it acts beyond this project's files in a way demo_cli does not "
                               f"read ({'; '.join(what[:3]) or command[:60]}): neither the runtime net "
                               f"nor a checkpoint can capture that.")
        if "git" in tools:
            c.matched_rule = "git_unread"                  # the net cannot capture .git
        elif tools & _SQL_CLIENTS:
            c.matched_rule, c.action_type = "sql_unread", "sql"
        else:
            c.matched_rule = "unread_code" if route == "runner" else "not_understood"
        _, mismatches, _ = self._context(command, _Facts(), intent, actual_env, None)
        needs = _needs_the_net(command) if route == "runner" and c.matched_rule == "unread_code" else None
        (supervisable, net_name, rewrite, group_id, entry, checkpoint_skipped,
         checkpoint_taken) = self._runtime_net_or_checkpoint(
            c, None, None, command, dialect, can_supervise, mismatches,
            affected_paths=sorted(impact.destroys),
            checkpoint_ok=needs != _SPAWNS,
            # V21: a runner's outside operand refuses the checkpoint (V17), not
            # the net - which still watches what the code does in the project.
            net_outside_ok=route == "runner")
        if supervisable or entry is not None:
            return _Facts(entry=entry, affected_paths=sorted(impact.destroys),
                          group_id=group_id or (entry or {}).get("group"),
                          supervisable=supervisable, net_name=net_name, rewrite=rewrite,
                          checkpoint_skipped=checkpoint_skipped,
                          checkpoint_taken=checkpoint_taken, c=c)
        if route == "runner" and c.matched_rule == "unread_code":
            runners = sorted({u.split()[0] for u in impact.uncovered})
            if needs:
                # Rb2: with no net, these runners escalate (policy rows).
                return _Facts(entry=None, checkpoint_skipped=checkpoint_skipped, c=c,
                              note=f"It {needs} ({', '.join(runners)}), and no runtime net was "
                                   f"available to capture what that changes.")
            f = self._engine_facts(command, dialect, c, impact, target_path, explicit_db, db_url)
            f.note = (f"It runs code demo_cli does not read ({', '.join(runners)}); no runtime "
                      f"net was available, so nothing that code changes is captured or watched.")
            return f
        return _Facts(entry=None, checkpoint_skipped=checkpoint_skipped, c=c)

    def _engine_facts(self, command: str, dialect: str, c: Classification, impact,
                      target_path: Optional[str], explicit_db: Optional[str],
                      db_url: Optional[str]) -> _Facts:
        from .engine.verdict import assess
        from .engine.effects import RUN
        from . import policy

        a = assess(impact, self.config)

        affected_paths, target, entry = [], None, None
        snap_notes, strategy = {}, "snapshot"
        checkpoint_skipped, checkpoint_taken = None, False
        supervisable, net_name, rewrite, group_id = False, None, None, None

        c.is_destructive = c.is_mutating = c.is_sql_mutating = False
        c.is_file_writer = c.remote_exec = False
        c.nonrecoverable_surface = None; c.destructive_segments = 0; c.run_surfaces = []
        # keep c.matched_rule / c.action_type / c.segments: they are receipt labels only

        # 1. Escalating remote surfaces
        if a.remote_escalated:
            c.nonrecoverable_surface = policy.surface_of(a.remote_escalated[0][0])
            c.is_mutating = True
            c.is_destructive = True

        # 2. Unread execution (RUN)
        if any(knd == RUN for knd in impact.remote.values()):
            c.remote_exec = True
            c.run_surfaces = sorted({policy.surface_of(lbl) for lbl, knd in impact.remote.items()
                                     if knd == RUN})

        # 3. Databases with no capture path
        if a.no_capture:
            c.is_mutating = True
            c.is_destructive = True

        # 4. Destroys (filesystem paths)
        c.destructive_segments = len(impact.destroys) + len(a.no_capture) + len(a.remote_escalated)
        if impact.destroys:
            c.is_mutating = True
            c.is_destructive = True
            all_ok = a.capturable
            if all_ok and not c.remote_exec:
                targets = [recovery.Target(
                    "dir" if (p in impact.destroyed_dirs or os.path.isdir(p)) else "file", p, p)
                    for p in sorted(impact.destroys.keys())]
                if impact.databases:
                    db_targets, db_ok = _db_targets(impact)
                    if db_ok:
                        targets.extend(db_targets)
                    else:
                        all_ok = False

                target = targets[0]
                affected_paths = [t.ref for t in targets if t.kind in ("file", "dir")]
                strategies = [(self.config.match_target(t.label).recovery if self.config.match_target(t.label) else "snapshot")
                              for t in targets]
                if any(s in ("none", "attest") for s in strategies) or not all_ok:
                    entry = None
                else:
                    reached = recovery.unignorable_dirs(command, dialect)
                    blast = list(set(impact.destroyed_dirs)
                                 | {p for p in impact.destroys if os.path.isdir(p)}
                                 | {t.ref for t in targets if t.kind == "dir"})
                    reached = reached | recovery.ignored_dirs_under(blast)
                    keep_out = (None if not reached
                                 else frozenset(recovery.IGNORED_DIRS) - reached)
                    entry = recovery.snapshot_set(targets, self.config.recovery_dir, strategy="snapshot",
                                                  action=command, notes=snap_notes, ignore_dirs=keep_out)
        elif impact.databases:
            c.is_mutating = True
            c.is_destructive = True
            db_targets, all_db_ok = _db_targets(impact)
            if all_db_ok and db_targets and not a.no_capture and not a.remote_escalated and not c.remote_exec:
                target = db_targets[0]
                affected_paths = [t.ref for t in db_targets if t.kind in ("file", "dir")]
                strategies = [(self.config.match_target(t.label).recovery if self.config.match_target(t.label) else "snapshot")
                              for t in db_targets]
                if any(s in ("none", "attest") for s in strategies):
                    entry = None
                else:
                    entry = recovery.snapshot_set(db_targets, self.config.recovery_dir, strategy="snapshot",
                                                  action=command, notes=snap_notes)

        # 5. Nothing destroyed, no escalating remote, no no_capture -> ALLOW
        if (not impact.destroys and not impact.databases
                and not a.remote_escalated and not a.no_capture):
            c.is_destructive = False
            c.is_mutating = False
            c.matched_rule = None
            target = None
            entry = None

        # A target the user names is captured only where a local copy can
        # stand for the change - never beside an escalating remote surface or
        # unread execution. _legacy_facts has always refused those two
        # (is_snapshot_eligible); the engine path took the snapshot anyway
        # (M2.2b1). A database nothing captures does not cancel it: the user
        # asked for this target (test_cross_rule_multiplicity).
        if target_path and not (a.remote_escalated or c.remote_exec):
            ap_tp = os.path.abspath(target_path)
            tgt_kind = "dir" if os.path.isdir(ap_tp) else "file"
            user_tgt = recovery.Target(tgt_kind, ap_tp, ap_tp)
            target = user_tgt
            affected_paths = [ap_tp]
            entry = recovery.snapshot(user_tgt, self.config.recovery_dir, strategy="snapshot",
                                      action=command, notes=snap_notes)
            c.is_destructive = True
            c.is_mutating = True

        if entry:
            group_id = entry.get("group")

        # A change the policy ALLOWS is still a change: name it, so a reader is
        # not told a branch deletion was "non-mutating" (M2.2a, ruling (c)).
        listed = sorted(k for k, kind in impact.remote.items()
                        if policy.remote_decision(kind) == policy.ALLOW)

        return _Facts(target=target, entry=entry, affected_paths=affected_paths,
                      snap_notes=snap_notes, group_id=group_id, supervisable=supervisable,
                      net_name=net_name, rewrite=rewrite, checkpoint_skipped=checkpoint_skipped,
                      checkpoint_taken=checkpoint_taken, remote_pg=False, strategy=strategy, c=c,
                      remote_listed=listed)

    def _legacy_facts(self, command: str, dialect: str, c: Classification,
                      target_path: Optional[str], explicit_db: Optional[str],
                      db_url: Optional[str], can_supervise: bool,
                      intent: Intent, actual_env: Optional[str],
                      engine_error: Optional[str] = None) -> _Facts:
        # B0 (msg 037): legacy reads less than the engine. When the engine could not
        # finish, legacy may keep a STRICTER answer (a capture, an escalation), never
        # its ALLOW: an unread command is "not understood" -> runtime net,
        # checkpoint, or escalate. r''m a.txt was ALLOW with nothing captured.
        if engine_error and not c.needs_recovery and not c.remote_exec and not c.nonrecoverable_surface:
            c.is_mutating = True
            c.matched_rule = ENGINE_UNAVAILABLE          # "engine_unavailable", a receipt label

        # cp / sed -i / perl -i ONTO AN EXISTING FILE destroy it, and no
        # classifier rule says so. The rule cannot live in the classifier: it
        # is filesystem-blind, and a vote there for `cp a new.txt` escalates an
        # ordinary `rm x && cp a b` (test_posix_copy_does_not_count_as_a_
        # destructive_step). So the vote is cast here, where we can stat, and
        # only for a target that exists. It IS a vote: without it
        # `DROP TABLE t; cp -f a b` would snapshot b and call the whole line
        # REVERSIBLE - see multi_destructive below.
        #
        # In-place formatters (prettier --write f.js, black f.py) vote too.
        # They were classified as writers and counted by nobody, so
        # `git reset --hard; prettier --write f.js` came back REVERSIBLE.
        overwriting = recovery.overwrites(command, dialect)
        if overwriting:
            c.is_destructive = c.is_mutating = True
            c.matched_rule = c.matched_rule or overwriting[0]
        c.destructive_segments += (len(overwriting)
                                   + recovery.target_writer_segments(command, dialect))

        # Writing to a path that does NOT yet exist CREATES it - there is nothing
        # to destroy. classify.py is filesystem-blind (string only), so the
        # correction happens here, where we can stat.
        #
        # Extended past `>` to the PowerShell cmdlets with the same shape:
        # Set-Content / Out-File / New-Item make a new file, and a
        # Move/Copy/Rename -Force onto a free name clobbers nothing.
        #
        # The distinction that matters: a name that RESOLVES but is absent from
        # disk means creation, so the flag is cleared. A name that does not
        # resolve at all is AMBIGUOUS and keeps its classification, so it still
        # escalates - never quietly waved through.
        if c.matched_rule == "fs_redirect_truncate":
            # RESOLVED-AND-ABSENT IS THE ONLY CASE THAT CLEARS. This used to be
            # `redirect_target(command)` on the raw line, and `if not rt or
            # not exists(rt)` - so "I could not find the target" cleared the
            # flag exactly like "the target is new". The comment above has
            # always said the opposite, and the code was the thing that was
            # wrong: five spellings of a truncating redirect reached ALLOW
            # against an existing file with no snapshot and no receipt
            # (2026-09-08). recovery.resolve_redirect_target reads the same
            # effective, substituted segments the classifier judged, so the
            # two can no longer disagree about what the command touches.
            rt, resolved = recovery.resolve_redirect_target(command, dialect)
            if resolved and not os.path.exists(rt) and _nothing_else_acts(c):
                c.is_destructive = False
                c.is_mutating = False
                c.matched_rule = None
        elif c.matched_rule in _CREATES_IF_MISSING:
            # Same three-way split as the redirect branch above: only
            # RESOLVED-AND-ABSENT means "creates". An unresolvable name -
            # $env:APPDATA\notes.txt, $(Get-Date).txt - used to come back as a
            # literal that os.path.exists denied, and was read as creation.
            named, resolved = recovery.ps_named_target(command, dialect)
            if resolved and not os.path.exists(named) and _nothing_else_acts(c):
                c.is_destructive = False
                c.is_mutating = False
                c.matched_rule = None

        # The concrete file list an rm / mv will touch (brace/glob-expanded),
        # surfaced so the preview can PRINT it - the file count the agent was
        # actually asking for (claude-code#76626). Empty for non rm / mv.
        affected_paths = recovery.expanded_operands(command, dialect)

        # Whether the USER named a target, captured before the block below
        # overwrites target_path with whatever extraction found. The two mean
        # very different things and sharing one name has already cost a fix.
        user_named_target = target_path is not None

        # Trou 2: when no target was supplied explicitly, resolve the real
        # filesystem operand of an rm / mv so the snapshot actually fires on the
        # auto-fire path (the flagship "rm -> undo" moment). Bounded to the
        # project root so we never try to copy a home/system tree, and honest
        # about multi-path rm (extract_path_operand returns None -> escalate).
        cand: Optional[str] = None
        if not target_path and not explicit_db and not db_url:
            cand = recovery.extract_path_operand(command, dialect)
            if cand:
                ap = os.path.abspath(cand)
                root = os.path.abspath(self.config.project_root or os.getcwd())
                # Strictly inside the root, by path and by real path. The root
                # itself is refused as a capture surface: a two-file rm at the
                # top level collapses to a common root of the whole project,
                # and silently deep-copying the entire tree on every such rm is
                # neither honest nor cheap. Escalate instead - same spirit as
                # _too_broad refusing $HOME / the filesystem root. A link out of
                # the project is refused too - see recovery.within_project.
                if recovery.within_project(ap, root) and os.path.exists(ap):
                    target_path = ap

        # THE DATABASE COMES FROM THE STATEMENT THAT WRITES IT (Part A3).
        # resolve_target takes the first .db name or postgres URL in what it
        # is given, and it was given the whole line: `echo app.db; sqlite3
        # data/users.db "DELETE ..."` snapshotted and previewed app.db, and an
        # echoed URL beat an operand the extractor had resolved. Now it reads
        # only the statements that act, and when those still name more than
        # one database - `ATTACH 'other.db'` - no target is guessed at all.
        db_text = recovery.acting_text(command, dialect)
        if (not (explicit_db or db_url or target_path)
                and len(recovery.db_mentions(db_text)) > 1):
            target = None
        else:
            target = recovery.resolve_target(db_text, explicit_db, db_url, target_path)

        # Trou #004: refuse a PARTIAL snapshot. For a filesystem delete/move whose
        # full operand set we could NOT resolve to an in-root capture (multiple
        # targets, or $()/backtick/globstar expansion we cannot evaluate), the
        # operand extractor returns None. resolve_target may still find a stray
        # .db name - but that covers only PART of what the command destroys. A
        # partial snapshot dressed up as REVERSIBLE is the exact lie this tool
        # exists to prevent, so drop the target and let the mutation escalate
        # honestly instead of claiming a recovery we did not fully take.
        #
        # THE SAME REFUSAL, FOR REDIRECTS. is_fs_delete covers rm / mv /
        # Remove-Item only, so a truncating redirect whose target set could
        # not be resolved walked straight past this and kept whatever stray
        # target resolve_target had found. `echo a > app.db; echo b > o2.db`
        # snapshotted app.db - picked up independently by the sqlite name
        # heuristic - and reported REVERSIBLE while o2.db was truncated with
        # nothing captured. An unearned REVERSIBLE, which is the one failure
        # this tool treats as unacceptable (2026-09-08).
        #
        # resolve_redirect_target already computes exactly the right answer
        # here: (None, False) for two redirecting segments. It was simply
        # being discarded by a path that never asked.
        # MORE THAN ONE SEGMENT DESTROYS SOMETHING, and a snapshot covers one.
        #
        # F2 closed the file-verb half of this in recovery.py - `rm a; mv b c`
        # no longer resolves a target. This is the half recovery.py cannot see:
        # a git or SQL destruction paired with a file delete. The operand
        # extractor resolves old.txt quite correctly, and the receipt then
        # claims a recovery point for a command that also dropped a table.
        #
        #     DROP TABLE users; rm old.txt      -> was REVERSIBLE
        #     git reset --hard; rm old.txt      -> was REVERSIBLE
        #
        # An explicit --target is left alone: the user named what they wanted
        # captured, and overriding that would be its own kind of dishonesty.
        multi_destructive = (c.destructive_segments > 1
                             and not user_named_target
                             and not explicit_db and not db_url)

        unresolved_redirect = (
            c.matched_rule == "fs_redirect_truncate"
            and not recovery.resolve_redirect_target(command, dialect)[1])
        if target is not None and (
                (target_path is None
                 and (recovery.is_fs_delete(command, dialect) or unresolved_redirect))
                or multi_destructive):
            target = None

        temp_f = _Facts(target=target)
        _, mismatches, _ = self._context(command, temp_f, intent, actual_env, None)

        # Snapshot the *real* target, honouring the per-target recovery strategy.
        label = target.label if target else None
        rule = self.config.match_target(label)
        strategy = rule.recovery if rule else "snapshot"

        # Managed / remote Postgres: a pg_dump over the wire is not a recovery
        # point we can stand behind for a system we don't control, so treat it
        # as a non-recoverable surface (honest escalation) instead of claiming
        # reversibility. Local Postgres (localhost) still snapshots normally.
        remote_pg = bool(target and target.kind == "postgres" and recovery.is_remote_pg(target.ref))
        if remote_pg and not c.nonrecoverable_surface:
            c.nonrecoverable_surface = "managed_database"

        # An ignored directory the command reaches into must be captured after
        # all - otherwise the snapshot silently omits part of the damage while
        # the entry looks complete. See recovery.unignorable_dirs.
        reached = recovery.unignorable_dirs(command, dialect)
        # THE ANCESTOR CASE, which the name-based question above cannot see.
        # `rm -rf proj` destroys proj/.git completely and names nothing
        # ignored, so `reached` was empty, the ignore list held, and the
        # capture was a subset reported REVERSIBLE (3 of 7 files, undo rc 0).
        #
        # The blast radius, not the capture root: scattered operands collapse
        # to a common root they do not destroy, and lifting the ignore there
        # would copy .git for a two-file delete.
        #
        # affected_paths is empty for anything that is not rm / mv, so a
        # PowerShell `Remove-Item -Recurse -Force proj` falls back to the
        # resolved directory target - the only other way this shape arrives.
        blast = affected_paths or (
            [target.ref] if target is not None and target.kind == "dir" else [])
        reached = reached | recovery.ignored_dirs_under(blast)
        keep_out = (None if not reached
                    else frozenset(recovery.IGNORED_DIRS) - reached)

        # Snapshot eligibility:
        # A snapshot is ONLY meaningful for a mutating action that can genuinely
        # be recovered locally. Opaque remote execution (fetch-and-run) and
        # non-recoverable surfaces (external infra/payment/cluster/managed DB)
        # cannot truthfully be recovered by a local snapshot, so we refuse to
        # capture phantom snapshots that would pollute the recovery index and
        # falsely suggest an escalated or unrecoverable command was reversible.
        is_snapshot_eligible = bool(
            c.needs_recovery
            and not c.remote_exec
            and not c.nonrecoverable_surface
            and not remote_pg
        )

        snap_notes: dict = {}
        entry = (recovery.snapshot(target, self.config.recovery_dir, strategy, action=command,
                                   ignore_dirs=keep_out, notes=snap_notes) if is_snapshot_eligible else None)

        (supervisable, net_name, rewrite, group_id, entry, checkpoint_skipped,
         checkpoint_taken) = self._runtime_net_or_checkpoint(
            c, target, entry, command, dialect, can_supervise, mismatches,
            cand=cand, affected_paths=affected_paths)

        return _Facts(target=target, entry=entry, affected_paths=affected_paths,
                      snap_notes=snap_notes, group_id=group_id, supervisable=supervisable,
                      net_name=net_name, rewrite=rewrite, checkpoint_skipped=checkpoint_skipped,
                      checkpoint_taken=checkpoint_taken, remote_pg=remote_pg, strategy=strategy, c=c,
                      engine_error=engine_error)

    def _context(self, command: str, f: _Facts, intent: Intent, actual_env: Optional[str],
                 approval_token: Optional[str]) -> Tuple[Context, List[Tuple[str, str, str]], bool]:
        label = f.target.label if f.target else None
        config_env = self.config.declared_env(label)
        ctx = build_context(command, target_label=label, declared_env=actual_env,
                            config_env=config_env, cwd=self.config.project_root)
        mismatches = compare_intent(intent, ctx)
        approval_ok = False
        key = self.config.approver_key
        if approval_token and key:
            approval_ok = approval.verify(command, approval_token, key)
        return ctx, mismatches, approval_ok

    def _decide(self, command: str, f: _Facts, ctx: Context, mismatches: list,
                approval_ok: bool) -> Decision:
        recovery_captured = f.entry is not None

        # Preview affected rows for previewable SQL on a recoverable target.
        preview_count, preview_rows, preview_cols = None, [], []
        if recovery_captured and is_sql_preview_candidate(command):
            preview_count, preview_rows, preview_cols = preview_mod.preview(command, f.target)

        decision = decide(
            f.c, ctx.environment, recovery_captured,
            mismatches=mismatches, approval_ok=approval_ok, preview_count=preview_count,
            supervisable=f.supervisable, net=f.net_name,
            env_declared=ctx.environment_source in ("declared", "config"),
        )

        # Say which kind of recovery this is. A whole-workspace checkpoint is
        # COARSE - undo restores the entire tree to its snapshot state, rolling
        # back unrelated edits made afterwards. Someone reading the receipt has
        # to be able to tell that from a one-file snapshot, and someone whose
        # action was blocked has to be told why the checkpoint was refused.
        reason = decision.reason
        if f.c.matched_rule == ENGINE_UNAVAILABLE:
            reason = (f"demo_cli could not finish reading this command (engine: {f.engine_error}), "
                      f"so it is treated as not understood. {reason}")
        if f.checkpoint_taken:
            reason = (f"{reason} Recovery is a whole-workspace checkpoint "
                      f"(coarse): the target could not be resolved from the "
                      f"command text, so the whole project was preserved "
                      f"(nothing outside the project is captured). "
                      f"Undo restores the entire tree. The "
                      f"checkpoint is stored inside the project, so a command "
                      f"that deletes the whole project deletes it too.")
        elif f.checkpoint_skipped:
            reason = f"{reason} {checkpoint.reason_text(f.checkpoint_skipped, self.config)}"
        if decision.decision in ("REVERSIBLE", "DRY_RUN") and f.entry and (
            f.entry.get("kind") == "postgres" or any(e.get("kind") == "postgres" for e in f.entry.get("entries", []))
            or (f.target is not None and getattr(f.target, "kind", None) == "postgres")):
            reason = f"{reason} {recovery.PG_UNDO_LIMITS}"
        # A cap refusal is the one "no recovery point" a person can act on, so
        # it says which cap, and which knob. Only when nothing was captured -
        # a checkpoint may have covered the command after the cap refused.
        if f.entry is None and f.snap_notes.get("refused"):
            reason = f"{reason} {f.snap_notes['refused']}"
        if f.supervisable and f.group_id:
            reason = f"{reason} Undo with `demo_cli undo {f.group_id}`."
        if f.note:
            # An ALLOW decided by the note says only the note: "non-mutating"
            # would be untrue of code nobody read.
            reason = (f"Allowed: {f.note[0].lower()}{f.note[1:]}"
                      if decision.decision == ALLOW else f"{reason} {f.note}")
        if f.remote_listed:
            from . import policy
            names = ", ".join(f.remote_listed[:3])
            if len(f.remote_listed) > 3:
                names += f", +{len(f.remote_listed) - 3} more"
            reason = (f"{reason} Recorded and allowed: {names} "
                      f"(if it has to come back: {policy.recovery_hint(policy.surface_of(f.remote_listed[0]))}).")

        # THE RECEIPT IS NOT THE PERSON. Everything above appended to a local
        # `reason` that only ever reached the Receipt, while every adapter
        # shows result.decision.reason - so the checkpoint explanation, whose
        # own comment says "someone whose action was blocked has to be told why
        # the checkpoint was refused", was told to the ledger and to nobody
        # else. Put the augmented text back on the decision so the two agree
        # and the adapters carry it without each having to remember.
        decision.reason, decision.preview_count = reason, preview_count
        decision.preview_rows, decision.preview_cols, decision.mismatches = preview_rows, preview_cols, mismatches
        return decision

    def _record(self, command: str, c: Classification, f: _Facts, ctx: Context,
                decision: Decision, intent: Intent, prediction, dialect: str,
                agent_id: str, session_id: str,
                decided_by: Optional[str] = None) -> GuardResult:
        preview_count = getattr(decision, "preview_count", None)
        preview_rows, preview_cols = getattr(decision, "preview_rows", []), getattr(decision, "preview_cols", [])
        mismatches = getattr(decision, "mismatches", [])
        gid = f.group_id or (f.entry.get("group") if f.entry else None)
        receipt = Receipt(
            action_raw=command, action_type=c.action_type, target_environment=ctx.environment,
            decision=decision.decision, reason=decision.reason, mode=self.mode,
            matched_rule=c.matched_rule,
            classification="destructive" if c.is_destructive else ("mutating" if c.is_mutating else "safe"),
            recovery_point=f.entry["recovery_point"] if f.entry else None,
            nonrecoverable_surface=c.nonrecoverable_surface, dry_run_affected_rows=preview_count,
            context=ctx.as_dict(), declared_intent=intent.as_dict(),
            context_mismatches=[list(m) for m in mismatches],
            pipeline_segments=c.segments if c.is_pipeline else [], remote_exec=c.remote_exec,
            dialect=dialect, agent_id=agent_id, session_id=session_id,
            prediction=prediction, group_id=gid, approvable=decision.approvable,
            decided_by=decided_by)
        _record_receipt(self.config.receipts_path, receipt)

        return GuardResult(
            command=command, classification=c, context=ctx, decision=decision, mode=self.mode,
            target=f.target, recovery_entry=f.entry, preview_count=preview_count,
            preview_rows=preview_rows, preview_cols=preview_cols, mismatches=mismatches,
            affected_paths=f.affected_paths, receipt=receipt, prediction=prediction,
            rewrite=f.rewrite, group_id=gid, decided_by=decided_by)
    def _runtime_net_or_checkpoint(
        self,
        c: Classification,
        target: Optional[recovery.Target],
        entry: Optional[dict],
        command: str,
        dialect: str,
        can_supervise: bool,
        mismatches: list,
        cand: Optional[str] = None,
        affected_paths: Optional[List[str]] = None,
        checkpoint_ok: bool = True,
        net_outside_ok: bool = False,
    ) -> Tuple[bool, Optional[str], Optional[str], Optional[str], Optional[dict], Optional[str], bool]:
        is_sql = bool(c.is_sql_mutating or c.action_type == "sql" or (c.matched_rule and c.matched_rule.startswith("sql_")))
        is_git = bool(c.matched_rule and c.matched_rule.startswith("git_"))
        is_ps = bool(dialect == POWERSHELL or (c.matched_rule and c.matched_rule.startswith("ps_")))
        proj_root = os.path.abspath(self.config.project_root or os.getcwd())
        raw_ops = recovery._path_operands(command) if (c.needs_recovery and dialect == POSIX) else []
        targets_out_of_project = bool(
            (cand and not recovery.within_project(os.path.abspath(cand), proj_root))
            or (affected_paths and any(not recovery.within_project(os.path.abspath(p), proj_root) for p in affected_paths))
            or (raw_ops and any(os.path.isabs(p) and not recovery.within_project(os.path.abspath(p), proj_root) for p in raw_ops))
        )
        r1_applies = bool(
            c.needs_recovery
            and target is None
            and entry is None
            and not c.nonrecoverable_surface
            and not c.remote_exec
            and not mismatches
            and not is_sql
            and not is_git
            and (net_outside_ok or not targets_out_of_project)
        )

        supervisable = False
        net_name = None
        rewrite = None
        group_id = None

        if r1_applies:
            if os.name == "nt":
                from . import mountstate
                st = mountstate.status(self.config)
                if st.running is True and st.mountpoint:
                    if _mount_covers_project(st.mountpoint, proj_root):
                        supervisable = True
                        net_name = "mount"
            else:
                from . import syscall_guard
                if can_supervise and syscall_guard.available() and not is_ps:
                    supervisable = True
                    net_name = "syscall_guard"
                    import shlex, uuid
                    group_id = uuid.uuid4().hex[:8]
                    rewrite = f"{_launcher(proj_root)} sh -g {group_id} {shlex.quote(command)}"

        checkpoint_skipped, checkpoint_taken = None, False
        if supervisable:
            pass  # Syscall guard or WinFsp mount replaces checkpoint
        # V17 (2026-10-08): a checkpoint copies THIS project. When an operand
        # lies outside it, the copy cannot bring that file back, and calling
        # the line REVERSIBLE on its strength was an unearned claim
        # (`rm -f /elsewhere/f $(date +%s)` with checkpoints on). It escalates.
        elif checkpoint_ok and not targets_out_of_project and checkpoint.should_checkpoint(
                c, target, self.config, recovery_captured=entry is not None):
            ck = checkpoint.capture(self.config, action=command)
            entry, checkpoint_skipped, checkpoint_taken = ck.entry, ck.skipped, ck.ok

        return supervisable, net_name, rewrite, group_id, entry, checkpoint_skipped, checkpoint_taken

    def evaluate_file_edit(
        self,
        file_path: str,
        tool_name: str = "Edit",
        intent: Optional[Intent] = None,
        agent_id: str = "unknown",
        session_id: str = "unknown",
    ) -> GuardResult:
        """Evaluate an agent file mutation (Edit / Write / MultiEdit / Notebook).

        This is the second door: agents mangle files through file-write tools,
        not only through Bash. We snapshot the *existing* file before it is
        overwritten so the change is reversible, and record a receipt. Creating
        a brand-new file has nothing to overwrite, so it proceeds with no
        snapshot. If an existing file cannot be snapshotted, we escalate rather
        than claim a recovery we did not take.
        """
        from .classify import Classification

        intent = intent or Intent()
        if self.config.config_error:
            return self._refuse_broken_config(f"{tool_name} {file_path}",
                                              agent_id, session_id)
        ap = os.path.abspath(file_path)
        hits = _control_plane_hits([ap], self.config)
        if hits:
            return self._refuse_control_plane(
                f"{tool_name} {ap}",
                Classification(is_mutating=True, action_type="filewrite",
                               matched_rule="control_plane", segments=[ap]),
                _files_reason(hits, self.config),
                ["Make this change yourself, outside the agent."],
                intent, agent_id, session_id, None)
        exists = os.path.exists(ap)
        is_dir = exists and os.path.isdir(ap)

        # Bound to the project root, like evaluate() and syscall_guard.
        # _in_scope. Applied BEFORE the snapshot, so an out-of-root file is
        # never copied into this project's recovery dir. The root itself is
        # refused for evaluate()'s reason: copying the whole tree on every
        # edit is neither honest nor cheap.
        root = os.path.abspath(self.config.project_root or os.getcwd())
        try:
            within = os.path.commonpath([ap, root]) == root
        except ValueError:                      # different drives on Windows
            within = False
        in_scope = recovery.within_project(ap, root)
        # Inside by path, outside by where the bytes live: a link out.
        links_out = within and ap != root and not in_scope

        c = Classification(
            is_mutating=exists, is_destructive=exists, action_type="filewrite",
            matched_rule=f"file_{tool_name.lower()}", segments=[ap],
        )

        target = (recovery.Target("dir" if is_dir else "file", ap, ap)
                  if exists and in_scope else None)
        label = target.label if target else None
        config_env = self.config.declared_env(label)
        ctx = build_context(f"{tool_name} {ap}", target_label=label,
                            config_env=config_env, cwd=self.config.project_root)

        rule = self.config.match_target(label)
        strategy = rule.recovery if rule else "snapshot"
        snap_notes: dict = {}
        entry = (recovery.snapshot(target, self.config.recovery_dir, strategy,
                                   action=f"{tool_name} {os.path.basename(ap)}",
                                   notes=snap_notes)
                 if exists and in_scope else None)
        recovery_captured = entry is not None

        mismatches = compare_intent(intent, ctx)
        decision = decide(c, ctx.environment, recovery_captured, mismatches=mismatches,
                          env_declared=ctx.environment_source in ("declared", "config"))
        if decision.decision == ESCALATE:
            if ap == root:
                decision.reason = (
                    f"{ap} is the project root itself; capturing the whole tree "
                    f"before an edit is neither honest nor cheap, so nothing was "
                    f"captured and nothing is claimed."
                )
                decision.next_steps = ["Name the file to edit, not the project root."]
            elif not in_scope:
                where = (f"{ap} links to {os.path.realpath(ap)}, outside the project "
                         f"root ({root})" if links_out else
                         f"{ap} is outside the project root ({root})")
                decision.reason = (
                    f"{where}; no recovery point was captured for it and none is "
                    f"claimed."
                )
                decision.next_steps = [
                    "Edit a path inside the project, or open that project "
                    "directly so demo_cli can cover it.",
                    "Take an independent backup if the edit must go ahead.",
                ]
            elif not recovery_captured:
                refused = snap_notes.get("refused")
                decision.reason = (
                    "Could not snapshot the file before editing; no recovery path."
                    + (f" {refused}" if refused else "")
                )
                decision.next_steps = (
                    ["Raise the cap named above, or edit a narrower target.",
                     "Or take an independent backup before editing."] if refused
                    else ["Check the file is readable and within the project root."]
                )

        receipt = Receipt(
            action_raw=f"{tool_name} {ap}",
            action_type="filewrite",
            target_environment=ctx.environment,
            decision=decision.decision,
            reason=decision.reason,
            mode=self.mode,
            matched_rule=c.matched_rule,
            classification="mutating",
            recovery_point=entry["recovery_point"] if entry else None,
            context=ctx.as_dict(),
            declared_intent=intent.as_dict(),
            agent_id=agent_id,
            session_id=session_id,
            approvable=decision.approvable,
        )
        _record_receipt(self.config.receipts_path, receipt)

        return GuardResult(
            command=f"{tool_name} {ap}", classification=c, context=ctx,
            decision=decision, mode=self.mode, target=target, recovery_entry=entry,
            receipt=receipt, mismatches=mismatches,
        )
