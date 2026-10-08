"""Where code runs later without anyone naming it (M2.2d).

A write to one of these places plants code: the next login shell, `cd` into
the folder, `git commit`, a boot or the scheduler runs it, and nobody types
its name. The engine already knows every path a line touches (redirections,
tee, cp, mv, ln, sed -i ...), so this module only has to recognise the place:
`World.finish` asks `place(path)` for each touched path and records
`reach("later:<place>", LATER)` - or, when the line only removed it and it
is a schedule (a hook, a unit / cron / autostart file), DELETE (ruling D4: a
schedule taken away). Removing a startup file, .envrc or a git config plants
nothing: an ordinary local change, captured like any other.

RULING D2 (Nizar, 2026-10-08): only places that run code on their own.
Makefile, package.json scripts, conftest.py and CI workflows run when someone
names them (make, npm test, pytest, a push): editing them is ordinary work,
captured as today, and they are NOT listed here.

The tools that plant code without writing a file this engine sees (crontab,
at, systemctl enable, schtasks, sc create, launchctl, reg Run keys, git
config) reach `later:` from their own resolvers.
"""
from __future__ import annotations

import os
from typing import Optional

# Under the home directory. Files, then directories (anything inside).
_HOME_FILES = (
    ".bashrc", ".bash_profile", ".bash_login", ".bash_logout", ".profile",
    ".zshrc", ".zshenv", ".zprofile", ".zlogin", ".zlogout",
    os.path.join(".config", "fish", "config.fish"),
    os.path.join(".ssh", "rc"),
    ".gitconfig", os.path.join(".config", "git", "config"),
)
_HOME_DIRS = (
    os.path.join(".config", "fish", "conf.d"),
    os.path.join(".config", "autostart"),
    os.path.join(".config", "systemd", "user"),
    os.path.join("Library", "LaunchAgents"),
    os.path.join("AppData", "Roaming", "Microsoft", "Windows", "Start Menu", "Programs",
                 "Startup"),
)
# PowerShell profiles: Documents\WindowsPowerShell\*profile.ps1 (5.1) and
# Documents\PowerShell\*profile.ps1 (7).
_PS_PROFILE_DIRS = (os.path.join("Documents", "WindowsPowerShell"),
                    os.path.join("Documents", "PowerShell"))
# Absolute, system-wide (Linux / macOS / Windows).
_SYSTEM_FILES = ("/etc/profile", "/etc/bash.bashrc", "/etc/zshrc", "/etc/zshenv",
                 "/etc/crontab", "/etc/rc.local", "/etc/ld.so.preload")
_SYSTEM_DIRS = ("/etc/profile.d", "/etc/zsh", "/etc/cron.d", "/etc/cron.hourly",
                "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly",
                "/var/spool/cron", "/etc/systemd/system", "/etc/systemd/user",
                "/lib/systemd/system", "/usr/lib/systemd/system", "/etc/init.d",
                "/etc/xdg/autostart", "/Library/LaunchAgents", "/Library/LaunchDaemons",
                r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp")


# The hooks git runs, by exact name (githooks(5), git 2.51 - copied from its
# HOOKS section, 28 names). Any other name in a hooks folder - pre-commit.sample
# included - is never run.
GIT_HOOKS = frozenset({
    "applypatch-msg", "pre-applypatch", "post-applypatch", "pre-commit",
    "pre-merge-commit", "prepare-commit-msg", "commit-msg", "post-commit", "pre-rebase",
    "post-checkout", "post-merge", "pre-push", "pre-receive", "update", "proc-receive",
    "post-receive", "post-update", "reference-transaction", "push-to-checkout",
    "pre-auto-gc", "post-rewrite", "sendemail-validate", "fsmonitor-watchman",
    "p4-changelist", "p4-prepare-changelist", "p4-post-changelist", "p4-pre-submit",
    "post-index-change",
})


def _norm(p: str) -> str:
    return os.path.normcase(os.path.normpath(p))


def _inside(path: str, folder: str) -> bool:
    return path.startswith(folder.rstrip("\\/") + os.sep)


def schedule(path: str, home: Optional[str] = None) -> bool:
    """Is `path` a schedule - a hook git runs, or a file in a folder a
    scheduler or the session starts things from? Removing one takes a
    schedule away (ruling D4). Removing any other place (a startup file,
    .envrc, a git config) plants nothing: it is an ordinary local change,
    captured like any other."""
    p = _norm(path)
    home = _norm(home or os.path.expanduser("~"))
    parts = p.split(os.sep)
    if len(parts) >= 3 and parts[-3] == ".git" and parts[-2] == "hooks":
        return parts[-1] in GIT_HOOKS
    if _inside(p, home) and any(_inside(p, _norm(os.path.join(home, d))) for d in _HOME_DIRS
                                if "fish" not in d):
        return True
    return any(_inside(p, _norm(d)) for d in _SYSTEM_DIRS if "profile" not in d and "zsh" not in d)


def place(path: str, home: Optional[str] = None) -> Optional[str]:
    """The name of the auto-run place `path` is, or None. Absolute paths."""
    p = _norm(path)
    home = _norm(home or os.path.expanduser("~"))
    parts = p.split(os.sep)
    name = parts[-1]
    # Anywhere: direnv runs .envrc on `cd`; git runs .git/hooks/<a hook name>
    # and reads .git/config (hooksPath, aliases, filters: git_ops claims
    # `git config`).
    if name == ".envrc":
        return path
    for k in range(len(parts) - 1):
        if parts[k] != ".git":
            continue
        if parts[k + 1] == "hooks" and k + 3 == len(parts) and name in GIT_HOOKS:
            return path
        if parts[k + 1] == "config" and k + 2 == len(parts):
            return path
    if _inside(p, home):
        rel = p[len(home) + 1:]
        if rel in (_norm(f) for f in _HOME_FILES):
            return os.path.join("~", rel)
        if any(_inside(p, _norm(os.path.join(home, d))) for d in _HOME_DIRS):
            return os.path.join("~", rel)
        if (any(_inside(p, _norm(os.path.join(home, d))) for d in _PS_PROFILE_DIRS)
                and name.endswith("profile.ps1")):
            return os.path.join("~", rel)
    if p in (_norm(f) for f in _SYSTEM_FILES):
        return path
    if any(_inside(p, _norm(d)) for d in _SYSTEM_DIRS):
        return path
    return None
