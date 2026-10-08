"""What a system command changes on THIS machine (M2.2c): services, power,
processes, accounts, disks, the machine's own recovery data, the network and
firewall, file modes and owners, and the Windows registry - on Linux, and the
Windows tools Git Bash runs.

None of these is a file in the project: `reach(label, kind)` and policy.py
decides. Labels (policy._LABEL_SURFACES):
  service:<manager>@<where>  -> service_control   (ask)
  power:<where>              -> host_power        (ask)
  process:<where>            -> process_control   (ask)
  account:<where>            -> account_control   (deny)
  device:<disk or volume>    -> disk_format       (deny)
  sysrec:<what>              -> system_recovery   (deny)
  net:<firewall|link>@<where>-> host_network      (ask)
  owner:<where>              -> file_ownership    (ask)
  winreg:<root key>          -> system_config     (ask)

RULINGS C1-C10 (Nizar, 2026-10-07):
  C1 a service stopped, killed, masked, disabled, isolated = SERVICE_LOSS; its
     definition changed or removed = OVERWRITE / DELETE; started, restarted,
     reloaded, unmasked = SERVICE_KEEP (allowed and listed); reads read.
  C2 reboot, power-off, halt, suspend, logoff = SERVICE_LOSS on host_power;
     cancelling, warning or showing a shutdown reads.
  C3 a process signalled (kill, pkill, killall, taskkill, wmic ... terminate)
     = SERVICE_LOSS on process_control; every process at once (kill -1,
     kill 1, killall5) on host_power. Listing signals and `kill -0` read.
  C4 any account write, ADDITIONS included (a new account or a new sudo
     member is a way back in), on account_control; reads read.
  C5 a disk wiped, formatted or repartitioned on disk_format; listing reads.
  C6 shadow copies, backups, boot configuration and event logs - what a
     recovery of this machine would use - on system_recovery.
  C7 the firewall and the network links on host_network: a flush or delete =
     DELETE, a rule or setting = OVERWRITE, a link taken down = SERVICE_LOSS.
  C8 chmod of a path IN the project is captured (a directory snapshot
     restores every mode: VERIFIED 2026-10-07), so it is REVERSIBLE; outside
     the project it escalates (verdict: outside). chown / chgrp / icacls
     grant|deny|setowner / takeown escalate anywhere on file_ownership: a
     restore by an ordinary user cannot give ownership back.
  C9 a registry write on system_config; `reg export` / `reg save` write a
     local file.
  C10 scheduling is M2.2d's (rulings D1-D4, 2026-10-08): planting code that
     runs later - crontab, at, schtasks /create, systemctl enable / link /
     preset / add-wants, systemd-run --on-*, launchctl load, sc create or a new
     binPath, a registry Run key - is LATER on `later:` (deferred_execution,
     ask); taking a schedule away (crontab -r, atrm, schtasks /delete) is
     DELETE there; listing one reads.

WHAT IT CLAIMS, AND WHAT IT DOES NOT. A command word, verb or object this
module does not list is `uncovered`, and today's path decides the line. A verb
that is itself an expansion is not understood. Any other expanding word can
only turn a change into a read (`kill $X` with X=-l), so the change is
claimed (may-semantics).

WINDOWS TOOLS FROM GIT BASH. Their switches are case-insensitive and written
`/x`, and Git Bash's path conversion makes people write `//x`; most also take
`-x`. All three spellings are read alike. The tool may receive a converted
path instead of the switch and fail - the change is still claimed.

VERIFIED (2026-10-07), each from the tool's own help, never by running a
change on this machine:
  - systemd 259: `systemctl --help` (verbs and options, GENERATED into
    system_data.py); systemctl(1): --dry-run is honoured by the power verbs
    and default / rescue / emergency / exit only; reboot / halt / poweroff /
    shutdown --help (-w and -k only write a record or a warning; -c cancels).
  - /usr/sbin/service (init-system-helpers): `service NAME ACTION`, the
    ACTION passed on to systemctl or the init script; --status-all.
  - procps 4 pkill, psmisc killall, bash `help kill`.
  - shadow-utils userdel / usermod / passwd / chpasswd / groupdel, adduser's
    deluser / delgroup --help.
  - util-linux wipefs (no -a / -o: lists only; -n: no write), fdisk, sfdisk,
    blkdiscard, mkfs; parted 3 --help.
  - iptables 1.8.13 --help and iptables-restore --help (from the Debian
    package, run with no network); ufw 0.36.2 parser.py / frontend.py
    (`[--dry-run] [--force] COMMAND`, case-insensitive); nft --help;
    iproute2 `ip help` and its abbreviations, run in an empty network
    namespace (`unshare -rn`): `ip l s lo down` = link set, `ip a d` =
    delete, `ip a f` = flush, `ip a` = show; nmcli per-object help.
  - coreutils chmod / chown / chgrp --help.
  - Windows 11 `/?` of reg, sc, net, taskkill, shutdown, vssadmin, wbadmin,
    bcdedit, wevtutil, cipher, format, icacls, takeown, netsh advfirewall,
    wmic (diskpart was not run: it asks for elevation).
  - launchctl (macOS) is documentation-only (ruling R4): only escalations
    are claimed, every other word is uncovered.
"""
from __future__ import annotations

import os
from typing import List, Optional, Tuple

from ..model import Word
from .cloud_ops import READ
from .effects import CREATE, DELETE, LATER, OVERWRITE, SERVICE_KEEP, SERVICE_LOSS


# ---------------------------------------------------------------- shared

def _reach(w, label: str, kind: Optional[str]) -> None:
    if kind is not None and kind != READ:
        w.impact.reach(label, kind)


def _args(inv) -> List[Word]:
    return list(inv.argv[1:])


def _first_expands(w, inv, word: Optional[Word], tool: str) -> bool:
    """A deciding word that is an expansion: not understood."""
    if word is not None and word.expands:
        w.impact.not_understood(inv.text, f"the {tool} command is named by an expansion")
        return True
    return False


def _win(v: str) -> str:
    """A Windows switch or word, as the tool reads it: case-insensitive,
    `//x` (Git Bash's escape) read as `/x`."""
    v = v.lower()
    return v[1:] if v.startswith("//") else v


def _switch(v: str) -> Optional[str]:
    """`/x`, `//x` or `-x` -> `x`; anything else -> None."""
    v = _win(v)
    if v[:1] in ("/", "-") and len(v) > 1:
        return v[1:]
    return None


def _help_only(args: List[Word], names=("--help", "-h", "--version", "-V")) -> bool:
    return any(not a.expands and a.value in names for a in args)


# ---------------------------------------------------------------- C1 / C2: systemctl

# Verb -> what it does (ruling C1). Verbs not listed here but in the tool's
# own list are M2.2d's (unit files that make code run later) or uncovered.
_SC_READ = frozenset({
    "list-units", "list-automounts", "list-paths", "list-sockets", "list-timers", "is-active",
    "is-failed", "status", "show", "cat", "help", "list-dependencies", "whoami",
    "list-unit-files", "is-enabled", "get-default", "list-machines", "list-jobs",
    "show-environment", "is-system-running"})
_SC_KEEP = frozenset({"start", "reload", "restart", "try-restart", "reload-or-restart",
                      "try-reload-or-restart", "thaw", "unmask", "reset-failed",
                      "daemon-reload", "daemon-reexec"})
_SC_LOSS = frozenset({"stop", "kill", "freeze", "isolate", "mask", "disable", "cancel"})
_SC_OVERWRITE = frozenset({"set-property", "bind", "mount-image", "edit", "set-default",
                           "set-environment", "unset-environment", "import-environment",
                           "service-watchdogs"})
_SC_DELETE = frozenset({"clean", "revert"})
# Unit files wired to start on their own (ruling D2): code that runs later.
_SC_LATER = frozenset({"enable", "reenable", "link", "preset", "preset-all", "add-wants",
                       "add-requires"})
# Read with no argument, a setting with one.
_SC_SETTING = frozenset({"log-level", "log-target", "service-log-level", "service-log-target"})
_SC_POWER = frozenset({"default", "rescue", "emergency", "halt", "poweroff", "reboot", "kexec",
                       "soft-reboot", "exit", "switch-root", "sleep", "suspend", "hibernate",
                       "hybrid-sleep", "suspend-then-hibernate"})
# systemctl(1): --dry-run "currently supported by verbs" - these only.
_SC_DRY = frozenset({"halt", "poweroff", "reboot", "kexec", "suspend", "hibernate",
                     "hybrid-sleep", "suspend-then-hibernate", "default", "rescue",
                     "emergency", "exit"})
# Starting one of these targets IS the power action.
_POWER_TARGETS = frozenset(f"{t}.target" for t in (
    "poweroff", "reboot", "halt", "kexec", "rescue", "emergency", "shutdown", "sleep",
    "suspend", "hibernate", "hybrid-sleep", "suspend-then-hibernate", "soft-reboot",
    "ctrl-alt-del", "exit"))


def _long_match(v: str, names) -> Optional[str]:
    """getopt_long: a unique prefix of a long option is that option."""
    name = v.split("=", 1)[0]
    if name in names:
        return name
    hits = [n for n in names if n.startswith(name)]
    return hits[0] if len(hits) == 1 else None


def systemctl(w, inv, parsed, state, tool) -> None:
    from .system_data import SYSTEMCTL_FLAGS, SYSTEMCTL_VALUES, SYSTEMCTL_VERBS
    args = _args(inv)
    longs = [o for o in SYSTEMCTL_VALUES + SYSTEMCTL_FLAGS if o.startswith("--")]
    verb_word: Optional[Word] = None
    rest: List[Word] = []
    opts = {}
    i = 0
    while i < len(args):
        a = args[i]
        v = a.value
        if not a.expands and v == "--":
            rest.extend(args[i + 1:])
            break
        if not a.expands and v.startswith("--"):
            name = _long_match(v, longs)
            if name is None:
                return w.impact.not_covered("systemctl " + v.split("=", 1)[0])
            if name in SYSTEMCTL_VALUES and "=" not in v:
                opts[name] = args[i + 1] if i + 1 < len(args) else None
                i += 2
                continue
            opts[name] = Word(v, v.split("=", 1)[1], a.start, a.end) if "=" in v else None
            i += 1
            continue
        if not a.expands and v.startswith("-") and len(v) > 1:
            j = 1
            while j < len(v):
                o = "-" + v[j]
                if o in SYSTEMCTL_VALUES:
                    glued = v[j + 1:]
                    if glued:
                        opts[o] = Word(glued, glued, a.start, a.end)
                    else:
                        opts[o] = args[i + 1] if i + 1 < len(args) else None
                        i += 1
                    break
                if o not in SYSTEMCTL_FLAGS:
                    return w.impact.not_covered("systemctl " + o)
                opts[o] = None
                j += 1
            i += 1
            continue
        if verb_word is None:
            verb_word = a
        else:
            rest.append(a)
        i += 1
    if any(k in opts for k in ("--help", "-h", "--version")):
        return
    if verb_word is None:
        return                                            # list-units
    if _first_expands(w, inv, verb_word, "systemctl"):
        return
    verb = verb_word.value
    if verb not in SYSTEMCTL_VERBS:
        return w.impact.not_covered(f"systemctl {verb}")
    host = opts.get("--host") or opts.get("-H") or opts.get("--machine") or opts.get("-M")
    where = (host.raw if host.expands else host.value) if host is not None else "local"
    manager = "systemd-user" if "--user" in opts else "systemd"
    label = f"service:{manager}@{where}"
    if verb in _SC_POWER:
        if "--dry-run" in opts and verb in _SC_DRY:
            return
        return _reach(w, f"power:{where}", SERVICE_LOSS)
    if verb in _SC_READ:
        return
    if verb in _SC_SETTING:
        return _reach(w, label, OVERWRITE if rest else None)
    if verb in ("start", "restart", "reload-or-restart", "try-restart",
                "try-reload-or-restart") and any(
            not u.expands and u.value in _POWER_TARGETS for u in rest):
        return _reach(w, f"power:{where}", SERVICE_LOSS)
    if verb in _SC_KEEP:
        return _reach(w, label, SERVICE_KEEP)
    if verb in _SC_LOSS:
        return _reach(w, label, SERVICE_LOSS)
    if verb in _SC_OVERWRITE:
        return _reach(w, label, OVERWRITE)
    if verb in _SC_DELETE:
        return _reach(w, label, DELETE)
    if verb in _SC_LATER:
        return _reach(w, f"later:{manager}@{where}", LATER)
    w.impact.not_covered(f"systemctl {verb}")


def service(w, inv, parsed, state, tool) -> None:
    """`service NAME ACTION`; the ACTION goes to systemctl or the init script."""
    args = _args(inv)
    if not args:
        return w.impact.not_covered("service")
    first = args[0]
    if not first.expands and first.value in ("--status-all", "--help", "-h", "--version", "-V"):
        return
    if not first.expands and first.value.startswith("--h"):
        return                                            # the script reads --h* as help
    if len(args) < 2:
        return w.impact.not_covered("service")
    action = args[1]
    if _first_expands(w, inv, action, "service") or _first_expands(w, inv, first, "service"):
        return
    a = action.value
    label = "service:sysv@local"
    if a in ("stop", "force-stop"):
        return _reach(w, label, SERVICE_LOSS)
    if a in ("start", "restart", "reload", "force-reload", "try-restart", "--full-restart",
             "condrestart"):
        return _reach(w, label, SERVICE_KEEP)
    if a == "status":
        return
    w.impact.not_covered(f"service {a}")


def launchctl(w, inv, parsed, state, tool) -> None:
    """macOS, documentation only (ruling R4): only escalations are claimed."""
    args = _args(inv)
    if not args or args[0].expands:
        return w.impact.not_covered("launchctl")
    sub = args[0].value
    if sub in ("stop", "unload", "bootout", "remove", "disable", "kill"):
        return _reach(w, "service:launchd@local", SERVICE_LOSS)
    if sub == "reboot":
        return _reach(w, "power:local", SERVICE_LOSS)
    if sub in ("load", "bootstrap", "enable", "submit"):
        return _reach(w, "later:launchd@local", LATER)
    w.impact.not_covered(f"launchctl {sub}")


# ---------------------------------------------------------------- C2: power

def power(w, inv, parsed, state, tool) -> None:
    """reboot / halt / poweroff (systemd's compatibility commands)."""
    args = _args(inv)
    if _help_only(args, ("--help",)) or any(
            not a.expands and a.value in ("-w", "--wtmp-only") for a in args):
        return                                            # -w writes the wtmp record only
    _reach(w, "power:local", SERVICE_LOSS)


_WIN_SHUTDOWN_ACT = frozenset({"s", "sg", "r", "g", "p", "h", "l", "hybrid", "o", "fw"})


def shutdown(w, inv, parsed, state, tool) -> None:
    """Linux (systemd) shutdown, or Windows shutdown.exe from Git Bash: both
    readings, the one that loses more (may-semantics)."""
    args = _args(inv)
    vals = [a.value for a in args if not a.expands]
    sw = {_switch(v) for v in vals} - {None}
    if "?" in sw or "--help" in vals:
        return
    win_acts = sw & _WIN_SHUTDOWN_ACT
    where = "local"
    for k, a in enumerate(args):
        if not a.expands and _switch(a.value) == "m" and k + 1 < len(args):
            where = args[k + 1].value
    if win_acts:
        return _reach(w, f"power:{where}", SERVICE_LOSS)
    # Linux: -c cancels, -k only warns, --show shows; Windows: /a aborts, and
    # none of these shuts down on either system.
    if sw & {"c", "k", "a"} or "--show" in vals:
        return
    _reach(w, f"power:{where}", SERVICE_LOSS)


# ---------------------------------------------------------------- C3: processes

def kill(w, inv, parsed, state, tool) -> None:
    """bash's kill builtin and /usr/bin/kill: `-l` / `-L` list signals,
    signal 0 only tests. PID 1 or -1 is every process (host_power)."""
    args = _args(inv)
    if not args:
        return
    targets: List[Word] = []
    signal: Optional[str] = None
    i = 0
    while i < len(args):
        a = args[i]
        v = a.value
        if a.expands:
            targets.append(a)
            i += 1
            continue
        if v == "--":
            targets.extend(args[i + 1:])
            break
        if signal is None and not targets and v in ("-l", "-L", "--list", "--table", "--help",
                                                     "-V", "--version"):
            return
        if signal is None and not targets and v in ("-s", "-n", "--signal"):
            nxt = args[i + 1] if i + 1 < len(args) else None
            signal = (nxt.value if nxt is not None and not nxt.expands else "?")
            i += 2
            continue
        if signal is None and not targets and v.startswith("-") and len(v) > 1:
            signal = v[1:]
            i += 1
            continue
        targets.append(a)
        i += 1
    if signal in ("0", "SIG0"):
        return                                            # tests the process, sends nothing
    if not targets:
        return
    every = any(not t.expands and t.value in ("1", "-1") for t in targets)
    _reach(w, "power:local" if every else "process:local", SERVICE_LOSS)


def pkill(w, inv, parsed, state, tool) -> None:
    args = _args(inv)
    if _help_only(args):
        return
    if tool == "killall" and any(not a.expands and a.value in ("-l", "--list") for a in args):
        return
    _reach(w, "process:local", SERVICE_LOSS)


def killall5(w, inv, parsed, state, tool) -> None:
    _reach(w, "power:local", SERVICE_LOSS)


def taskkill(w, inv, parsed, state, tool) -> None:
    args = _args(inv)
    sw = [_switch(a.value) for a in args if not a.expands]
    if "?" in sw:
        return
    where = "local"
    for k, a in enumerate(args):
        if not a.expands and _switch(a.value) == "s" and k + 1 < len(args):
            where = args[k + 1].value
    _reach(w, f"process:{where}", SERVICE_LOSS)


def wmic(w, inv, parsed, state, tool) -> None:
    words = [_win(a.value) for a in _args(inv) if not a.expands]
    if any(_switch(v) == "?" for v in words):
        return
    if "shadowcopy" in words and "delete" in words:
        return _reach(w, "sysrec:vss", DELETE)
    if "process" in words and ("delete" in words or "terminate" in words):
        return _reach(w, "process:local", SERVICE_LOSS)
    w.impact.not_covered("wmic")


# ---------------------------------------------------------------- C4: accounts

_ACCOUNT_DELETE = frozenset({"userdel", "groupdel", "deluser", "delgroup"})
_ACCOUNT_WRITE = frozenset({"useradd", "adduser", "groupadd", "addgroup", "usermod", "groupmod",
                            "chpasswd", "chgpasswd", "gpasswd", "chsh", "chfn", "newusers",
                            "chage", "passwd"})


def account(w, inv, parsed, state, tool) -> None:
    args = _args(inv)
    vals = [a.value for a in args if not a.expands]
    if any(v in ("--help", "-h", "--version", "-V") for v in vals) and tool != "chage":
        return
    if tool == "passwd" and any(v in ("-S", "--status") for v in vals):
        return
    if tool == "chage" and any(v in ("-l", "--list", "-h", "--help") for v in vals):
        return
    _reach(w, "account:local", DELETE if tool in _ACCOUNT_DELETE else OVERWRITE)


# ---------------------------------------------------------------- net.exe (accounts, shares, services)

def net(w, inv, parsed, state, tool) -> None:
    args = _args(inv)
    if not args or args[0].expands:
        return w.impact.not_covered("net")
    sub = _win(args[0].value)
    rest = args[1:]
    plain = [a for a in rest if a.expands or _switch(a.value) is None]
    sws = {_switch(a.value) for a in rest if not a.expands} - {None}
    sw_names = {s.split(":", 1)[0] for s in sws}
    if sub in ("help", "helpmsg") or "?" in sw_names:
        return
    if sub == "stop":
        return _reach(w, "service:net@local", SERVICE_LOSS) if plain else None
    if sub == "start":
        return _reach(w, "service:net@local", SERVICE_KEEP) if plain else None
    if sub in ("user", "localgroup", "group"):
        # `net user`, `net user NAME`, `net localgroup GROUP` read; a password,
        # a member, or any switch but /domain writes.
        writes = len(plain) >= 2 or bool(sw_names - {"domain"})
        if not writes:
            return
        return _reach(w, "account:local", DELETE if "delete" in sw_names or "del" in sw_names
                      else OVERWRITE)
    if sub == "accounts":
        return _reach(w, "account:local", OVERWRITE) if (sw_names - {"domain"}) else None
    if sub == "share":
        # Kept on the surface the old rule gave `net share NAME /delete`.
        if "delete" in sw_names:
            return _reach(w, "account:local", DELETE)
        if any("=" in a.value for a in plain if not a.expands) or (sw_names - {"delete"}):
            return _reach(w, "account:local", OVERWRITE)
        return
    w.impact.not_covered(f"net {sub}")


# ---------------------------------------------------------------- sc.exe

_SCEXE_READ = frozenset({"query", "queryex", "qc", "qdescription", "qfailure", "qfailureflag",
                         "qsidtype", "qprivs", "qtriggerinfo", "qpreferrednode",
                         "qmanagedaccount", "qprotection", "quserservice", "sdshow", "showsid",
                         "enumdepend", "getdisplayname", "getkeyname"})
_SCEXE_KEEP = frozenset({"start", "continue", "interrogate"})
_SCEXE_LOSS = frozenset({"stop", "pause", "control"})
_SCEXE_OVERWRITE = frozenset({"config", "description", "failure", "failureflag", "sidtype",
                              "privs", "managedaccount", "sdset", "triggerinfo",
                              "preferrednode", "boot"})


def sc(w, inv, parsed, state, tool) -> None:
    args = _args(inv)
    where = "local"
    if args and not args[0].expands and args[0].value.startswith("\\\\"):
        where, args = args[0].value, args[1:]
    if not args:
        return w.impact.not_covered("sc")
    if _first_expands(w, inv, args[0], "sc"):
        return
    cmd = _win(args[0].value)
    if _switch(cmd) == "?" or any(not a.expands and _switch(a.value) == "?" for a in args[1:]):
        return
    label = f"service:sc@{where}"
    if cmd in _SCEXE_READ:
        return
    if cmd in _SCEXE_KEEP:
        return _reach(w, label, SERVICE_KEEP)
    if cmd in _SCEXE_LOSS:
        return _reach(w, label, SERVICE_LOSS)
    if cmd == "create" or (cmd == "config" and any(
            not a.expands and _win(a.value).startswith("binpath=") for a in args[1:])):
        return _reach(w, f"later:sc@{where}", LATER)      # the program the service runs
    if cmd in _SCEXE_OVERWRITE:
        return _reach(w, label, OVERWRITE)
    if cmd == "delete":
        return _reach(w, label, DELETE)
    w.impact.not_covered(f"sc {cmd}")


# ---------------------------------------------------------------- C5: disks

def _devices(args: List[Word], skip_values=()) -> List[str]:
    out, i = [], 0
    while i < len(args):
        a = args[i]
        if not a.expands and a.value in skip_values:
            i += 2
            continue
        if a.expands or not a.value.startswith("-"):
            out.append(a.raw if a.expands else a.value)
        i += 1
    return out


def _device(w, devs: List[str], kind: str) -> None:
    for d in devs or ["?"]:
        _reach(w, f"device:{d}", kind)


def wipefs(w, inv, parsed, state, tool) -> None:
    args = _args(inv)
    vals = [a.value for a in args if not a.expands]
    if _help_only(args) or any(v in ("-n", "--no-act") for v in vals):
        return
    erase = any(v in ("-a", "--all") or v.startswith(("-o", "--offset"))
                or (v.startswith("-") and not v.startswith("--") and ("a" in v[1:] or "o" in v[1:]))
                for v in vals)
    if not erase:
        return                                            # VERIFIED: no -a / -o lists only
    _device(w, _devices(args, ("-o", "--offset", "-t", "--types", "-O", "--output", "-b",
                               "--backup")), DELETE)


def fdisk(w, inv, parsed, state, tool) -> None:
    args = _args(inv)
    vals = [a.value for a in args if not a.expands]
    if _help_only(args):
        return
    reads = {"-l", "--list", "-x", "--list-details"} if tool == "fdisk" else {
        "-l", "--list", "-d", "--dump", "-J", "--json", "-s", "--show-size", "-g",
        "--show-geometry", "-V", "--verify", "-F", "--list-free", "-n", "--no-act", "-r"}
    writes = {"--delete", "--reorder", "--move-data", "-A", "--activate", "--relocate",
              "-N", "--wipe", "-w", "--wipe-partitions"}
    if tool == "sfdisk" and "-r" in vals:
        writes.add("-r")                                  # -r is --reorder for sfdisk
        reads.discard("-r")
    if any(v in reads for v in vals) and not any(v.split("=")[0] in writes for v in vals):
        return
    _device(w, _devices(args, ("-b", "--sector-size", "-u", "--units", "-L", "--color",
                               "-o", "--output", "-t", "--type", "-X", "--label",
                               "-N", "-w", "--wipe", "-W", "--wipe-partitions")), OVERWRITE)


_PARTED_WRITES = frozenset({"mklabel", "mktable", "mkpart", "rm", "resizepart", "rescue", "name",
                            "set", "toggle", "disk_set", "disk_toggle", "type", "mkpartfs"})


def parted(w, inv, parsed, state, tool) -> None:
    args = _args(inv)
    vals = [a.value for a in args if not a.expands]
    if _help_only(args) or ("-l" in vals or "--list" in vals) and len(
            [v for v in vals if not v.startswith("-")]) == 0:
        return
    words = [v for v in vals if not v.startswith("-")]
    if "print" in words and not (set(words) & _PARTED_WRITES):
        return
    devs = [v for v in words if v.startswith("/dev/")] or words[:1]
    _device(w, devs, DELETE if "rm" in words or "mklabel" in words or "mktable" in words
            else OVERWRITE)


def blkdiscard(w, inv, parsed, state, tool) -> None:
    args = _args(inv)
    if _help_only(args):
        return
    _device(w, _devices(args, ("-o", "--offset", "-l", "--length", "-p", "--step")), DELETE)


def mkfs(w, inv, parsed, state, tool) -> None:
    args = _args(inv)
    if any(not a.expands and a.value in ("--help", "-h") for a in args):
        return
    devs = [d for d in _devices(args, ("-t", "--type", "-L", "-b", "-C", "-N", "-m", "-O",
                                        "-E", "-T", "-U", "-I", "-c")) if not d.isdigit()]
    _device(w, devs[:1], DELETE)


def winformat(w, inv, parsed, state, tool) -> None:
    args = _args(inv)
    if any(not a.expands and _switch(a.value) == "?" for a in args):
        return
    vols = [a.value for a in args if not a.expands and _switch(a.value) is None]
    _device(w, vols[:1], DELETE)


def diskpart(w, inv, parsed, state, tool) -> None:
    args = _args(inv)
    if any(not a.expands and _switch(a.value) == "?" for a in args):
        return
    _reach(w, "device:diskpart", OVERWRITE)               # a script, or commands on stdin


def cipher(w, inv, parsed, state, tool) -> None:
    sws = [_switch(a.value) or "" for a in _args(inv) if not a.expands]
    if any(s.startswith("w") for s in sws) and "?" not in sws:
        return _reach(w, "device:freespace", DELETE)     # wipes what deleted files left
    w.impact.not_covered("cipher")


# ---------------------------------------------------------------- C6: the machine's recovery data

def vssadmin(w, inv, parsed, state, tool) -> None:
    words = [_win(a.value) for a in _args(inv) if not a.expands]
    if not words or "/?" in words or words[0] == "list":
        return
    if words[0] in ("delete", "resize"):
        return _reach(w, "sysrec:vss", DELETE)
    w.impact.not_covered(f"vssadmin {words[0]}")


def wbadmin(w, inv, parsed, state, tool) -> None:
    words = [_win(a.value) for a in _args(inv) if not a.expands]
    if not words or "/?" in words or words[0] == "get":
        return
    if words[0] == "delete":
        return _reach(w, "sysrec:wbadmin", DELETE)
    if words[0] == "disable":
        return _reach(w, "sysrec:wbadmin", OVERWRITE)
    w.impact.not_covered(f"wbadmin {words[0]}")


_BCD_READ = frozenset({"enum", "v", "?", "help"})


def bcdedit(w, inv, parsed, state, tool) -> None:
    sws = [_switch(a.value) for a in _args(inv) if not a.expands]
    acts = [s for s in sws if s is not None and s not in ("store", "v")]
    if not acts or all(s in _BCD_READ for s in acts):
        return
    if "export" in acts and len(acts) == 1:
        return w.impact.not_covered("bcdedit /export")
    _reach(w, "sysrec:bcd", DELETE if {"delete", "deletevalue"} & set(acts) else OVERWRITE)


def wevtutil(w, inv, parsed, state, tool) -> None:
    words = [_win(a.value) for a in _args(inv) if not a.expands]
    if not words or _switch(words[0]) == "?":
        return
    c = words[0]
    if c in ("cl", "clear-log"):
        return _reach(w, "sysrec:eventlog", DELETE)
    if c in ("sl", "set-log", "im", "install-manifest", "um", "uninstall-manifest"):
        return _reach(w, "sysrec:eventlog", OVERWRITE)
    if c in ("el", "enum-logs", "gl", "get-log", "ep", "enum-publishers", "gp", "get-publisher",
             "qe", "query-events", "gli", "get-log-info"):
        return
    w.impact.not_covered(f"wevtutil {c}")


# ---------------------------------------------------------------- C7: network and firewall

_IPT_DELETE = frozenset("FXD")
_IPT_WRITE = frozenset("AIRPNEZ")
_IPT_LONG = {"--append": "A", "--check": "C", "--delete": "D", "--insert": "I", "--replace": "R",
             "--list": "L", "--list-rules": "S", "--flush": "F", "--zero": "Z", "--new": "N",
             "--new-chain": "N", "--delete-chain": "X", "--policy": "P", "--rename-chain": "E",
             "--help": "h", "--version": "V"}


def iptables(w, inv, parsed, state, tool) -> None:
    """The command is an option (-A, -F, ...); getopt_long, so long names may
    be abbreviated. Every word is read as a possible command: a value that
    looks like one can only make the result stricter."""
    args = _args(inv)
    if tool.endswith("-restore"):
        if any(not a.expands and a.value in ("-t", "--test", "-h", "--help", "-V", "--version")
               for a in args):
            return
        return _reach(w, "net:firewall@local", OVERWRITE)
    if tool.endswith("-save"):
        return
    cmds = set()
    for a in args:
        if a.expands:
            continue
        v = a.value
        if v.startswith("--"):
            name = _long_match(v, list(_IPT_LONG))
            if name:
                cmds.add(_IPT_LONG[name])
        elif v.startswith("-") and len(v) > 1 and not v[1:].isdigit():
            cmds.update(ch for ch in v[1:] if ch in _IPT_DELETE | _IPT_WRITE | set("LSCVh"))
    if cmds & _IPT_DELETE:
        return _reach(w, "net:firewall@local", DELETE)
    if cmds & _IPT_WRITE:
        return _reach(w, "net:firewall@local", OVERWRITE)
    if cmds:
        return                                            # -L, -S, -C, -h, -V
    w.impact.not_covered(tool)


def ufw(w, inv, parsed, state, tool) -> None:
    args = [a for a in _args(inv)]
    if args and not args[0].expands and args[0].value.lower() == "--dry-run":
        return                                            # VERIFIED: parse_command, dryrun
    if args and not args[0].expands and args[0].value.lower() in ("--force", "-f"):
        args = args[1:]
    if not args:
        return w.impact.not_covered("ufw")
    if _first_expands(w, inv, args[0], "ufw"):
        return
    c = args[0].value.lower()
    if c in ("status", "show", "help", "--help", "-h", "version", "--version"):
        return
    if c == "app":
        sub = args[1].value.lower() if len(args) > 1 and not args[1].expands else ""
        return None if sub in ("list", "info") else _reach(w, "net:firewall@local", OVERWRITE)
    if c in ("reset", "delete"):
        return _reach(w, "net:firewall@local", DELETE)
    if c == "route" and len(args) > 1 and not args[1].expands and args[1].value.lower() == "delete":
        return _reach(w, "net:firewall@local", DELETE)
    if c in ("enable", "disable", "reload", "default", "logging", "allow", "deny", "reject",
             "limit", "insert", "prepend", "route"):
        return _reach(w, "net:firewall@local", OVERWRITE)
    w.impact.not_covered(f"ufw {c}")


_NFT_DELETE = frozenset({"flush", "delete", "destroy"})
_NFT_WRITE = frozenset({"add", "insert", "replace", "create", "reset", "rename", "import"})
_NFT_READ = frozenset({"list", "describe", "monitor", "export", "get"})


def nft(w, inv, parsed, state, tool) -> None:
    args = _args(inv)
    vals = [a.value for a in args if not a.expands]
    if any(v in ("-h", "--help", "-v", "--version", "-V", "-c", "--check") for v in vals):
        return
    if any(v in ("-f", "--file", "-i", "--interactive") or v.startswith("--file=") for v in vals):
        return _reach(w, "net:firewall@local", OVERWRITE)
    words = []
    skip = False
    for a in args:
        if skip:
            skip = False
            continue
        if not a.expands and a.value in ("-D", "--define", "-I", "--includepath", "-d", "--debug"):
            skip = True
            continue
        if not a.expands and a.value.startswith("-"):
            continue
        if a.expands:
            w.impact.not_understood(inv.text, "an nft command named by an expansion")
            return
        words.extend(a.value.replace(";", " ; ").split())
    starts, new = [], True
    for t in words:
        if t == ";":
            new = True
            continue
        if new:
            starts.append(t)
            new = False
    if not starts:
        return
    if set(starts) & _NFT_DELETE:
        return _reach(w, "net:firewall@local", DELETE)
    if set(starts) & _NFT_WRITE:
        return _reach(w, "net:firewall@local", OVERWRITE)
    if set(starts) <= _NFT_READ:
        return
    w.impact.not_covered("nft " + starts[0])


_IP_OBJECTS = ("address", "addrlabel", "fou", "help", "ila", "ioam", "l2tp", "link", "macsec",
               "maddress", "monitor", "mptcp", "mroute", "mrule", "neighbor", "neighbour",
               "netconf", "netns", "nexthop", "ntable", "ntbl", "route", "rule", "sr", "stats",
               "tap", "tcpmetrics", "token", "tunnel", "tuntap", "vrf", "xfrm")
_IP_READ_VERBS = ("show", "list", "lst", "get", "help", "save", "showdump", "monitor")
_IP_DELETE_VERBS = ("delete", "flush", "del")
_IP_WRITE_VERBS = ("add", "change", "replace", "append", "prepend", "set", "restore", "test",
                   "attach", "detach", "identify", "pids", "exec", "update", "load")
_IP_VALUE_OPTS = frozenset({"-f", "-family", "-l", "-loops", "-n", "-netns", "-rc", "-rcvbuf"})


def ip(w, inv, parsed, state, tool) -> None:
    """iproute2 matches object and command words by prefix (VERIFIED in an
    empty namespace). A prefix of both a read and a change is read as the
    change."""
    args = _args(inv)
    i = 0
    while i < len(args) and not args[i].expands and args[i].value.startswith("-"):
        v = args[i].value
        if v in ("-b", "-batch", "-force"):
            return w.impact.not_covered("ip -batch")
        if v in ("-V", "-Version", "-h", "-help"):
            return
        i += 2 if v in _IP_VALUE_OPTS else 1
    if i >= len(args):
        return
    if _first_expands(w, inv, args[i], "ip"):
        return
    o = args[i].value
    objs = [x for x in _IP_OBJECTS if x.startswith(o)]
    if not objs:
        return w.impact.not_covered(f"ip {o}")
    rest = args[i + 1:]
    if not rest:
        return                                            # `ip a`, `ip r`: show
    if _first_expands(w, inv, rest[0], "ip"):
        return
    v = rest[0].value
    if v == "help":
        return
    if any(x in ("netns", "vrf") for x in objs) and "exec".startswith(v):
        return w.impact.not_covered("ip netns exec")     # runs a command: today's path
    deletes = [x for x in _IP_DELETE_VERBS if x.startswith(v)]
    writes = [x for x in _IP_WRITE_VERBS if x.startswith(v)]
    reads = [x for x in _IP_READ_VERBS if x.startswith(v)]
    label = "net:link@local"
    if deletes:
        return _reach(w, label, DELETE)
    if writes:
        words = [a.value for a in rest[1:] if not a.expands and a.value != "dev"]
        if "down" in words:
            return _reach(w, label, SERVICE_LOSS)
        if words[-1:] == ["up"] and len(words) == 2 and len(rest) - 1 == len(
                [a for a in rest[1:] if not a.expands]):
            return _reach(w, label, SERVICE_KEEP)         # `ip link set eth0 up` only
        return _reach(w, label, OVERWRITE)
    if reads:
        return
    w.impact.not_covered(f"ip {o} {v}")


_NM_OBJECTS = ("general", "networking", "radio", "connection", "device", "agent", "monitor")
_NM_VALUE_OPTS = frozenset({"-c", "--colors", "-e", "--escape", "-f", "--fields", "-g",
                            "--get-values", "-m", "--mode", "-w", "--wait"})


def nmcli(w, inv, parsed, state, tool) -> None:
    args = _args(inv)
    i = 0
    while i < len(args) and not args[i].expands and args[i].value.startswith("-"):
        v = args[i].value
        if v in ("-h", "--help", "-v", "--version"):
            return
        i += 2 if v in _NM_VALUE_OPTS else 1
    if i >= len(args):
        return                                            # `nmcli`: status
    if _first_expands(w, inv, args[i], "nmcli"):
        return
    objs = [o for o in _NM_OBJECTS if o.startswith(args[i].value)]
    if len(objs) != 1:
        return w.impact.not_covered(f"nmcli {args[i].value}")
    obj = objs[0]
    rest = [a.value for a in args[i + 1:] if not a.expands]
    cmd = rest[0] if rest else ""
    label = "net:link@local"

    def is_(word, *names):
        return any(n.startswith(word) for n in names) if word else False
    if obj in ("monitor", "agent"):
        return w.impact.not_covered(f"nmcli {obj}")
    if obj == "networking":
        if not cmd or is_(cmd, "connectivity"):
            return
        return _reach(w, label, SERVICE_LOSS if is_(cmd, "off") else SERVICE_KEEP)
    if obj == "radio":
        if len(rest) < 2:
            return
        return _reach(w, label, SERVICE_LOSS if is_(rest[1], "off") else SERVICE_KEEP)
    if obj == "general":
        if not cmd or is_(cmd, "status", "permissions"):
            return
        if is_(cmd, "hostname", "logging") and len(rest) == 1:
            return
        return _reach(w, label, OVERWRITE)
    if obj == "connection":
        if not cmd or is_(cmd, "show", "monitor", "export"):
            if cmd and is_(cmd, "export") and len(rest) > 2:
                return w.impact.not_covered("nmcli connection export FILE")
            return
        if is_(cmd, "delete"):
            return _reach(w, label, DELETE)
        if is_(cmd, "down"):
            return _reach(w, label, SERVICE_LOSS)
        if is_(cmd, "up", "reload"):
            return _reach(w, label, SERVICE_KEEP)
        return _reach(w, label, OVERWRITE)
    # device
    if not cmd or is_(cmd, "status", "show", "monitor", "lldp"):
        return
    if is_(cmd, "wifi"):
        sub = rest[1] if len(rest) > 1 else ""
        if not sub or is_(sub, "list", "rescan", "show-password"):
            return
        return _reach(w, label, OVERWRITE)
    if is_(cmd, "delete"):
        return _reach(w, label, DELETE)
    if is_(cmd, "disconnect"):
        return _reach(w, label, SERVICE_LOSS)
    if is_(cmd, "connect", "reapply"):
        return _reach(w, label, SERVICE_KEEP)
    _reach(w, label, OVERWRITE)


def ifconfig(w, inv, parsed, state, tool) -> None:
    words = [a.value for a in _args(inv) if not a.expands]
    plain = [v for v in words if not v.startswith("-")]
    if len(plain) <= 1:
        return                                            # `ifconfig`, `ifconfig -a`, `ifconfig eth0`
    if "down" in plain:
        return _reach(w, "net:link@local", SERVICE_LOSS)
    if plain[1:] == ["up"]:
        return _reach(w, "net:link@local", SERVICE_KEEP)
    _reach(w, "net:link@local", OVERWRITE)


def netsh(w, inv, parsed, state, tool) -> None:
    words = [_win(a.value) for a in _args(inv) if not a.expands]
    if any(v in ("-r", "-f", "-u", "-p", "exec") for v in words):
        return w.impact.not_covered("netsh (remote or a script)")
    if not words or words[0] in ("/?", "?", "help"):
        return

    def pre(word, name):
        return bool(word) and name.startswith(word)
    ctx = words[0]
    rest = words[1:]
    cmd = rest[0] if rest else ""
    if pre(ctx, "advfirewall") or pre(ctx, "firewall"):
        if pre(ctx, "advfirewall") and pre(cmd, "firewall"):
            rest = rest[1:]
            cmd = rest[0] if rest else ""
        if not cmd or pre(cmd, "show") or pre(cmd, "dump") or cmd in ("?", "help"):
            return
        if pre(cmd, "export"):
            return w.impact.not_covered("netsh advfirewall export")
        if pre(cmd, "reset") or pre(cmd, "delete"):
            return _reach(w, "net:firewall@local", DELETE)
        return _reach(w, "net:firewall@local", OVERWRITE)
    if pre(ctx, "interface") and pre(cmd, "set"):
        down = any(v in ("admin=disabled", "disabled", "admin=disable", "connect=disconnected")
                   for v in rest)
        return _reach(w, "net:link@local", SERVICE_LOSS if down else OVERWRITE)
    w.impact.not_covered(f"netsh {ctx}")


# ---------------------------------------------------------------- C8: modes and owners

_CHMOD_MODE_START = frozenset("rwxXstugoa,+=01234567")
_CHMOD_LONG = ("--changes", "--silent", "--quiet", "--verbose", "--dereference",
               "--no-dereference", "--no-preserve-root", "--preserve-root", "--reference",
               "--recursive", "--help", "--version")


def chmod(w, inv, parsed, state, tool) -> None:
    """The mode of an existing path changes: captured as a destroy of that
    path (a directory whole), so the verdict captures it in the project and
    escalates it outside. An operand that is a symbolic link changes its
    target (chmod never changes a link)."""
    args = _args(inv)
    recursive, mode_seen, reference = False, False, False
    files: List[Word] = []
    done = False
    skip = False
    for a in args:
        if skip:
            skip = False
            continue
        v = a.value
        if done or a.expands or not v.startswith("-") or v == "-":
            if not mode_seen and not reference:
                if a.expands:
                    w.impact.not_understood(inv.text, "a chmod mode named by an expansion")
                    return
                mode_seen = True
                continue
            files.append(a)
            continue
        if v == "--":
            done = True
            continue
        if v.startswith("--"):
            name = _long_match(v, _CHMOD_LONG)
            if name is None:
                return w.impact.not_covered("chmod " + v.split("=", 1)[0])
            if name in ("--help", "--version"):
                return
            if name == "--recursive":
                recursive = True
            if name == "--reference":
                reference = True
                skip = "=" not in v                       # `--reference RFILE`
            continue
        if v[1] in _CHMOD_MODE_START and not mode_seen:
            mode_seen = True                              # `chmod -x f`: a mode, not options
            continue
        for ch in v[1:]:
            if ch == "R":
                recursive = True
            elif ch not in "cfvHLPh":
                return w.impact.not_covered("chmod -" + ch)
    paths = w.paths(files, state, inv)
    for p in paths:
        rp = os.path.realpath(p) if os.path.islink(p) else p
        n = w.node(state, rp)
        if not n.exists:
            continue
        if n.is_dir:
            w.within(state, rp, "MODE")                   # recursive or not: captured whole
        else:
            w.lose(n, "MODE")
            w.impact.touched.add(rp)


def chown(w, inv, parsed, state, tool) -> None:
    args = _args(inv)
    if _help_only(args, ("--help", "--version")):
        return
    _reach(w, "owner:local", OVERWRITE)


_ICACLS_WRITE = frozenset({"grant", "grant:r", "deny", "remove", "remove:g", "remove:d",
                           "setowner", "reset", "restore", "setintegritylevel", "substitute"})


def icacls(w, inv, parsed, state, tool) -> None:
    sws = [_switch(a.value) for a in _args(inv) if not a.expands]
    sws = [s for s in sws if s is not None]
    if "?" in sws:
        return
    if set(sws) & _ICACLS_WRITE:
        return _reach(w, "owner:local", OVERWRITE)
    if "save" in sws:
        return w.impact.not_covered("icacls /save")
    return                                                # display, /verify, /findsid


def takeown(w, inv, parsed, state, tool) -> None:
    sws = [_switch(a.value) for a in _args(inv) if not a.expands]
    if "?" in sws:
        return
    _reach(w, "owner:local", OVERWRITE)


# ---------------------------------------------------------------- C9: the registry

_REG_ROOTS = (("hkey_local_machine", "HKLM"), ("hkey_current_user", "HKCU"),
              ("hkey_classes_root", "HKCR"), ("hkey_users", "HKU"),
              ("hkey_current_config", "HKCC"), ("hklm", "HKLM"), ("hkcu", "HKCU"),
              ("hkcr", "HKCR"), ("hku", "HKU"), ("hkcc", "HKCC"))


def _reg_root(word: Optional[Word]) -> str:
    if word is None or word.expands:
        return "?"
    v = word.value
    if v.startswith("\\\\"):
        return v.split("\\")[2] if len(v.split("\\")) > 2 else v
    low = v.lower()
    for prefix, name in _REG_ROOTS:
        if low.startswith(prefix):
            return name
    return "?"


# Keys whose values Windows runs on its own (logon, any program start).
# Git Bash removes unquoted backslashes, so the key is compared with every
# separator dropped.
_AUTORUN_KEYS = ("currentversionrun", "currentversionrunonce", "currentversionrunservices",
                 "currentversionrunservicesonce", "currentversionpoliciesexplorerrun",
                 "currentversionwinlogon", "imagefileexecutionoptions",
                 "currentversionexplorershellfolders", "currentversionexplorerusershellfolders")


def _autorun_key(word: Optional[Word]) -> bool:
    if word is None or word.expands:
        return word is not None                           # an expansion may name one
    flat = word.value.lower().replace("\\", "").replace("/", "").replace(" ", "")
    return any(k in flat for k in _AUTORUN_KEYS)


def reg(w, inv, parsed, state, tool) -> None:
    args = _args(inv)
    if not args:
        return w.impact.not_covered("reg")
    if _first_expands(w, inv, args[0], "reg"):
        return
    op = _win(args[0].value)
    rest = args[1:]
    if _switch(op) == "?" or any(not a.expands and _switch(a.value) == "?" for a in rest):
        return
    if op in ("query", "compare"):
        return
    if op in ("export", "save"):
        plain = [a for a in rest if a.expands or _switch(a.value) is None]
        if len(plain) >= 2:
            for p in w.paths([plain[1]], state, inv):
                w.write(state, p, appending=False)
            return
        return w.impact.not_covered(f"reg {op}")
    key = next((a for a in rest if a.expands or _switch(a.value) is None), None)
    if op == "import":
        return _reach(w, "winreg:import", OVERWRITE)
    if op == "delete":
        return _reach(w, f"winreg:{_reg_root(key)}", DELETE)
    if op in ("add", "copy", "restore") and _autorun_key(key):
        return _reach(w, f"later:winreg:{_reg_root(key)}", LATER)
    if op in ("add", "copy", "restore", "load", "unload", "flags"):
        return _reach(w, f"winreg:{_reg_root(key)}", OVERWRITE)
    w.impact.not_covered(f"reg {op}")


# ---------------------------------------------------------------- C10 / M2.2d: schedulers

def crontab(w, inv, parsed, state, tool) -> None:
    """VERIFIED (cronie / Debian cron `crontab` usage): `-l` lists, `-r`
    removes, `-e` edits, `-n` only checks the syntax; a FILE, `-` or no
    operand at all replaces the table (no operand: from stdin)."""
    args = _args(inv)
    user = "local"
    flags, files = set(), []
    i = 0
    while i < len(args):
        a = args[i]
        v = a.value
        if not a.expands and v == "-u" and i + 1 < len(args):
            user = args[i + 1].raw if args[i + 1].expands else args[i + 1].value
            i += 2
            continue
        if not a.expands and v.startswith("-") and v != "-":
            flags.update(v[1:])
        else:
            files.append(a)
        i += 1
    label = f"later:crontab@{user}"
    if "h" in flags or "l" in flags or "n" in flags:
        return                                            # list, help, a syntax check
    if "r" in flags:
        return _reach(w, label, DELETE)
    _reach(w, label, LATER)                               # -e, a FILE, `-`, or stdin


def at(w, inv, parsed, state, tool) -> None:
    """VERIFIED (at 3.2.5, at(1)): -l = atq, -r / -d = atrm, -c prints jobs,
    -b = batch; -V alone prints the version (`at -V 10:00` still queues)."""
    args = [a for a in _args(inv)]
    vals = [a.value for a in args if not a.expands]
    if tool == "atq" or any(v in ("-l", "-c") for v in vals) or vals == ["-V"]:
        return                                            # list a queue, print a job, version
    if tool == "atrm" or any(v in ("-r", "-d") for v in vals):
        return _reach(w, "later:at@local", DELETE)
    _reach(w, "later:at@local", LATER)                    # at TIME / batch: a job from stdin or -f


def schtasks(w, inv, parsed, state, tool) -> None:
    args = _args(inv)
    sws = [_switch(a.value) for a in args if not a.expands]
    if "?" in sws:
        return
    where = "local"
    for k, a in enumerate(args):
        if not a.expands and _switch(a.value) == "s" and k + 1 < len(args):
            where = args[k + 1].value
    label = f"later:schtasks@{where}"
    if "create" in sws or "change" in sws:
        return _reach(w, label, LATER)
    if "delete" in sws:
        return _reach(w, label, DELETE)
    if "query" in sws or "showsid" in sws:
        return
    w.impact.not_covered("schtasks")                      # /run, /end: today's path


_SYSTEMD_RUN_LATER = ("--on-active", "--on-boot", "--on-startup", "--on-unit-active",
                      "--on-unit-inactive", "--on-calendar", "--on-clock-change",
                      "--on-timezone-change", "--path-property", "--socket-property",
                      "--timer-property")


def systemd_run(w, inv, parsed, state, tool) -> None:
    vals = [a.value for a in _args(inv) if not a.expands]
    if any(v.split("=", 1)[0] in _SYSTEMD_RUN_LATER for v in vals):
        return _reach(w, "later:systemd-run@local", LATER)
    w.impact.not_covered("systemd-run")                   # runs a command now: today's path


# ---------------------------------------------------------------- entry

_TOOLS = {
    "systemctl": systemctl, "service": service, "launchctl": launchctl,
    "reboot": power, "halt": power, "poweroff": power, "shutdown": shutdown,
    "kill": kill, "pkill": pkill, "killall": pkill, "killall5": killall5,
    "taskkill": taskkill, "wmic": wmic,
    "net": net, "net1": net, "sc": sc,
    "wipefs": wipefs, "fdisk": fdisk, "sfdisk": fdisk, "parted": parted,
    "blkdiscard": blkdiscard, "format": winformat, "format.com": winformat,
    "diskpart": diskpart, "cipher": cipher,
    "vssadmin": vssadmin, "wbadmin": wbadmin, "bcdedit": bcdedit, "wevtutil": wevtutil,
    "iptables": iptables, "ip6tables": iptables, "iptables-nft": iptables,
    "ip6tables-nft": iptables, "iptables-legacy": iptables, "ip6tables-legacy": iptables,
    "iptables-restore": iptables, "ip6tables-restore": iptables,
    "iptables-save": iptables, "ip6tables-save": iptables,
    "ufw": ufw, "nft": nft, "ip": ip, "nmcli": nmcli, "ifconfig": ifconfig, "netsh": netsh,
    "chmod": chmod, "chown": chown, "chgrp": chown, "icacls": icacls, "takeown": takeown,
    "reg": reg,
    "crontab": crontab, "at": at, "batch": at, "atq": at, "atrm": at, "schtasks": schtasks,
    "systemd-run": systemd_run,
}
for _t in _ACCOUNT_DELETE | _ACCOUNT_WRITE:
    _TOOLS[_t] = account
for _t in ("mkfs", "mke2fs", "mkswap", "mkdosfs", "mkfs.ext2", "mkfs.ext3", "mkfs.ext4",
           "mkfs.xfs", "mkfs.btrfs", "mkfs.vfat", "mkfs.fat", "mkfs.msdos", "mkfs.ntfs",
           "mkfs.exfat", "mkfs.f2fs", "mkntfs"):
    _TOOLS[_t] = mkfs

TOOLS: Tuple[str, ...] = tuple(sorted(_TOOLS))


def system(w, inv, parsed, state, tool) -> None:
    _TOOLS[tool](w, inv, parsed, state, tool)
