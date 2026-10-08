"""Tools a rule-table template cannot express (Part C, slice C1).

Each resolver is named by its rule in rules.py, which still holds the tool's
grammar, conditions and examples. A resolver receives the simulation (the
World), the Invocation, its parsed options and the state, and applies
effects through the World's primitives - write, edit, replace, within,
mkdir, copy, link, move, remove - so content origin, backups and devices are
handled in one place. Behaviour that was checked by running the real tool is
marked VERIFIED; the rest follows the tool's documentation.
"""
from __future__ import annotations

import fnmatch
import os
import re
from typing import List, Optional, Tuple

from ..model import Word
from .effects import DELETE, OVERWRITE, TRUNCATE
from .invocation import parse_options
from .rules import READ_ONLY, SHELLS

NEW = ""


def _update_none(parsed) -> None:
    """--update=none is -n by another name."""
    if [w.value for w in parsed.options.get("update", [])][-1:] == ["none"]:
        parsed.flags = parsed.flags | {"no_clobber"}


def _sub(word: Word, start: int, value: str) -> Word:
    """The part of `word` after `start` characters of its raw text (dd of=)."""
    raw = word.raw[start:]
    return Word(raw, value, word.start + start, word.end, expands=word.expands)


# ---- cp / mv / ln / install -------------------------------------------------

def cp(w, inv, parsed, state, tool) -> None:
    """VERIFIED: cp -n keeps an existing file; cp -b keeps it as f~."""
    if "attributes_only" in parsed.flags:
        return
    _update_none(parsed)
    paths = w.paths(parsed.operands, state, inv)
    pairs = w.dest_pairs(state, paths, parsed, inv)
    if "parents" in parsed.flags and len(paths) >= 2 and state.cwd:
        dest = paths[-1]
        pairs = [(p, os.path.normpath(os.path.join(dest, os.path.relpath(p, state.cwd))))
                 for p in paths[:-1]]
    for src, dst in pairs:
        w.copy(state, src, dst, parsed, "recursive" in parsed.flags)


def mv(w, inv, parsed, state, tool) -> None:
    _update_none(parsed)
    w.move(state, w.dest_pairs(state, w.paths(parsed.operands, state, inv), parsed, inv), parsed)


def ln(w, inv, parsed, state, tool) -> None:
    """VERIFIED: ln -sf replaces a file; ln without -f onto one fails."""
    paths = w.paths(parsed.operands, state, inv)
    for target, link in w.dest_pairs(state, paths, parsed, inv, single_into_cwd=True):
        w.link(state, target, link, parsed)


def install(w, inv, parsed, state, tool) -> None:
    paths = w.paths(parsed.operands, state, inv)
    if "directory" in parsed.flags:
        for p in paths:
            w.mkdir(state, p, True)
        return
    for src, dst in w.dest_pairs(state, paths, parsed, inv):
        if "create_leading" in parsed.flags:
            w.mkdir(state, os.path.dirname(dst), True)
        w.copy(state, src, dst, parsed, False)


# ---- in-place editors ---------------------------------------------------------

def _suffix(parsed) -> Optional[str]:
    words = parsed.options.get("in_place", [])
    return (words[-1].value or None) if words else None


def sed(w, inv, parsed, state, tool) -> None:
    """VERIFIED: sed -i.bak keeps the original as f.bak - still a destruction
    of f for demo_cli (review C1: the backup is the tool's). Without -i sed only
    prints. The first operand is the script unless -e/-f gave one. (A script's
    own w/W/e commands write or execute: not parsed - a known gap.)"""
    if "in_place" not in parsed.flags:
        return
    ops = list(parsed.operands)
    if not parsed.options.get("expression") and not parsed.options.get("file"):
        ops = ops[1:]
    for p in w.paths(ops, state, inv):
        w.edit(state, p, _suffix(parsed))


def perl(w, inv, parsed, state, tool) -> None:
    """perl -i rewrites its file operands. Without -i perl is running code this
    engine does not read: uncovered, like any interpreter (review ruling 3)."""
    if "in_place" not in parsed.flags:
        w.impact.not_covered("perl (code)")
        return
    ops = list(parsed.operands)
    if not parsed.options.get("code"):
        ops = ops[1:]                                   # the program file
    for p in w.paths(ops, state, inv):
        w.edit(state, p, _suffix(parsed))


def _writes(tool: str, parsed) -> bool:
    f, o = parsed.flags, parsed.options
    if tool == "prettier":
        return "write" in f and not ({"check", "list_different"} & f)
    if tool == "eslint":
        return "fix" in f and "fix_dry_run" not in f
    if tool == "black":
        return not ({"check", "diff", "version", "help"} & f) and not o.get("code")
    if tool == "isort":
        return not ({"check_only", "diff", "show_files", "version", "help", "stdout"} & f)
    if tool == "rustfmt":
        emit = [x.value for x in o.get("emit", [])]
        return not ({"check", "version", "help"} & f) and emit[-1:] != ["stdout"]
    if tool == "gofmt":
        return "write" in f
    return False


def formatter(w, inv, parsed, state, tool) -> None:
    """A file operand is rewritten in place; a directory, or a QUOTED glob the
    tool expands itself ("src/**/*.js"), may have anything under it rewritten,
    so it is captured whole (WITHIN)."""
    for key in ("output_file", "cpuprofile"):          # eslint -o, gofmt -cpuprofile
        for p in w.paths(parsed.options.get(key, []), state, inv):
            w.write(state, p, False)
    if not _writes(tool, parsed):
        return
    for word in parsed.operands:
        if word.quoted and any(c in word.value for c in "*?["):
            head = re.split(r"[*?\[]", word.value, maxsplit=1)[0]
            base = os.path.dirname(head) or "."
            for p in w.paths([Word(base, base, word.start, word.end)], state, inv):
                w.within(state, p, OVERWRITE)
            continue
        for p in w.paths([word], state, inv):
            n = w.node(state, p)
            if n.exists and n.is_dir:
                w.within(state, p, OVERWRITE)
            else:
                w.edit(state, p)


# ---- writers ------------------------------------------------------------------

def tee(w, inv, parsed, state, tool) -> None:
    """VERIFIED: tee -a appends."""
    for p in w.paths(parsed.operands, state, inv):
        w.write(state, p, "append" in parsed.flags)


_SIZE = re.compile(r"^([+\-<>/%]?)(\d+)([KMGTPEZYRQ](?:iB|B)?|[kmgtpezy]|)$")
_POW = "KMGTPEZYRQ"


def _bytes(num: str, unit: str) -> int:
    if not unit:
        return int(num)
    base = 1000 if unit.endswith("B") and not unit.endswith("iB") else 1024
    return int(num) * base ** (_POW.index(unit[0].upper()) + 1)


def truncate(w, inv, parsed, state, tool) -> None:
    """Shrinking destroys what is cut off; growing destroys nothing.
    An absolute size is compared with the file's current size."""
    size = parsed.options.get("size")
    ref = parsed.options.get("reference")
    if not size and not ref:
        return                                          # truncate refuses
    for p in w.paths(parsed.operands, state, inv):
        if w.device(p):
            continue
        n = w.node(state, p)
        if not n.exists:
            if "no_create" not in parsed.flags:
                w.create(state, p)
            continue
        if n.is_dir:
            continue
        shrink = True
        if size and not ref:
            m = _SIZE.match(size[-1].value)
            if m and "io_blocks" not in parsed.flags:
                op, num, unit = m.groups()
                if op in ("+", ">"):
                    shrink = False
                elif op == "":
                    try:
                        current = os.path.getsize(p) if n.origins == frozenset({p}) else None
                    except OSError:
                        current = None
                    shrink = current is None or _bytes(num, unit) < current
        if shrink:
            w.replace(state, p, TRUNCATE)
        else:
            w.impact.changes.add(p)
            w.impact.touched.add(p)


def shred(w, inv, parsed, state, tool) -> None:
    for p in w.paths(parsed.operands, state, inv):
        if w.device(p):
            continue
        n = w.node(state, p)
        if not n.exists or n.is_dir:
            continue
        if "remove" in parsed.flags:
            w.remove(state, p)
        else:
            w.replace(state, p, OVERWRITE)


def dd(w, inv, parsed, state, tool) -> None:
    """of=FILE is written (conv=notrunc still overwrites what it covers);
    with no of= dd writes to stdout."""
    of = [word for word in inv.argv[1:] if word.value.startswith("of=")]
    if not of:
        return
    word = _sub(of[-1], 3, of[-1].value[3:])
    for p in w.paths([word], state, inv):
        if w.device(p):
            continue
        n = w.node(state, p)
        if n.exists:
            if not n.is_dir:
                w.replace(state, p, OVERWRITE)
        else:
            w.write(state, p, False)


# ---- downloads (the request itself: send_ops, M2.2b4a) -------------------------

def _url_name(word: Word) -> Optional[str]:
    if word.expands:
        return None
    from urllib.parse import urlsplit                   # only curl / wget pay for it
    return os.path.basename(urlsplit(word.value).path) or None


def curl(w, inv, parsed, state, tool) -> None:
    f, o = parsed.flags, parsed.options
    if o.get("config"):
        w.impact.not_understood(inv.text, "curl reads more options from a file (-K)")
    urls = list(parsed.operands) + list(o.get("url", []))
    append = bool(o.get("continue_at"))
    names: List[Word] = [x for x in o.get("output", []) if x.value != "-"]
    if {"remote_name", "remote_name_all"} & f:
        if "remote_header_name" in f:
            w.impact.not_understood(inv.text, "curl -J takes the file name from the server")
        else:
            for u in urls[len(o.get("output", [])):]:
                if any(c in u.value for c in "[{") and "globoff" not in f:
                    w.impact.not_understood(inv.text, "curl expands a URL pattern into names")
                    continue
                name = _url_name(u)
                if name:
                    names.append(Word(name, name, u.start, u.end))
    outdir = w.paths(o.get("output_dir", [])[-1:], state, inv)
    for word in names:
        for p in w.paths([word], state, inv):
            if outdir and not os.path.isabs(word.value):
                p = os.path.normpath(os.path.join(outdir[0], word.value))
            if "create_dirs" in f:
                w.mkdir(state, os.path.dirname(p), True)
            w.write(state, p, append)
    for key in ("cookie_jar", "dump_header", "trace", "trace_ascii", "libcurl", "etag_save",
                "hsts", "alt_svc"):
        for p in w.paths([x for x in o.get(key, []) if x.value not in ("-", "%")], state, inv):
            w.write(state, p, False)
    w.untimed(_send_ops).curl_network(w, inv, parsed, state, tool)    # M2.2b4a: the request


def wget(w, inv, parsed, state, tool) -> None:
    """VERIFIED (man page): a plain `wget URL` never clobbers - the second copy
    is name.1; -O truncates like a redirect; -N may overwrite; -r/-p overwrite."""
    f, o = parsed.flags, parsed.options
    w.untimed(_send_ops).wget_network(w, inv, parsed, state, tool)    # M2.2b4a: the request
    for p in w.paths(o.get("output_file", []), state, inv):
        w.write(state, p, False)
    for p in w.paths(o.get("append_output", []), state, inv):
        w.write(state, p, True)
    if {"recursive", "mirror", "page_requisites", "content_disposition"} & f or o.get("input_file"):
        w.impact.not_understood(inv.text, "wget takes its file names from the server or a list")
        return
    doc = o.get("output_document")
    if doc:
        for p in w.paths([x for x in doc if x.value != "-"], state, inv):
            w.write(state, p, "continue" in f)
        return
    prefix = w.paths(o.get("directory_prefix", [])[-1:], state, inv)
    here = prefix[0] if prefix else state.cwd
    if here is None:
        w.impact.not_understood(inv.text, "the working directory is unknown")
        return
    for u in parsed.operands:
        name = _url_name(u) or "index.html"
        p = os.path.join(here, name)
        n = w.node(state, p)
        if not n.exists:
            w.write(state, p, False)
        elif "no_clobber" in f:
            continue
        elif "timestamping" in f:
            w.replace(state, p, OVERWRITE)
        elif "continue" in f:
            w.impact.changes.add(p)
        else:
            k = 1
            while w.node(state, f"{p}.{k}").exists:
                k += 1
            w.write(state, f"{p}.{k}", False)


_REMOTE_OPERAND = re.compile(r"^(?:rsync://|[^/]*:)")


def _rsync_host(v: str) -> str:
    """The host of an rsync remote operand: [USER@]HOST:PATH, [USER@]HOST::MODULE
    or rsync://[USER@]HOST[:PORT]/PATH (rsync(1), SYNOPSIS)."""
    if v.startswith("rsync://"):
        v = v[len("rsync://"):].split("/", 1)[0]
        return v.rsplit("@", 1)[-1].split(":", 1)[0]
    return v.split(":", 1)[0].rsplit("@", 1)[-1]


def rsync(w, inv, parsed, state, tool) -> None:
    """VERIFIED (M2.2f) against rsync(1) of rsync 3.5.0 (its Debian package's
    man page; the binary was not run). Locally: into an existing directory,
    anything under it may be overwritten or (--delete) removed, so it is
    captured whole. A PUSH to a host (ruling R8) is OVERWRITE on that host's
    filesystem, DELETE with any of the --del* family; a PULL is a local write.
    --dry-run / -n and --list-only change nothing; one SRC with no DEST lists."""
    f, o = parsed.flags, parsed.options
    ops = parsed.operands
    remote = [x for x in ops if not x.expands and _REMOTE_OPERAND.match(x.value)]
    if "dry_run" in f or "list_only" in f or len(ops) < 2:
        return
    if ops[-1] in remote:
        kind = DELETE if "delete" in f else OVERWRITE
        w.impact.reach(f"host:{_rsync_host(ops[-1].value)}", kind)
        if "remove_source_files" in f:
            for p in w.paths([x for x in ops[:-1] if x not in remote], state, inv):
                n = w.node(state, p)
                if n.exists and not n.is_dir:
                    w.remove(state, p)
        return
    for p in w.paths(o.get("log_file", []), state, inv):
        w.write(state, p, True)
    for key in ("write_batch", "only_write_batch"):
        for p in w.paths(o.get(key, []), state, inv):
            w.write(state, p, False)
    dests = w.paths(ops[-1:], state, inv)
    srcs = w.paths([x for x in ops[:-1] if x not in remote], state, inv)
    if not dests:
        return
    dest = dests[0]
    if "remove_source_files" in f:
        for p in srcs:
            n = w.node(state, p)
            if n.exists and not n.is_dir:
                w.remove(state, p)
    keep = "ignore_existing" in f              # --backup keeps the TOOL's copy: still lost
    backup = None
    if "backup" in f:
        if o.get("backup_dir"):
            w.impact.not_understood(inv.text, "rsync --backup-dir: where backups land")
        else:
            suffix = o.get("suffix")
            backup = dest + (suffix[-1].value if suffix else "~")
    dn = w.node(state, dest)
    single_file = len(srcs) == 1 and w.node(state, srcs[0]).exists and not w.node(state, srcs[0]).is_dir
    if dn.exists and dn.is_dir:
        if keep:
            return
        if single_file:
            target = os.path.join(dest, os.path.basename(srcs[0]))
            tn = w.node(state, target)
            if tn.exists and not tn.is_dir:
                w.replace(state, target, OVERWRITE)
            elif not tn.exists:
                w.write(state, target, False)
            return
        w.within(state, dest, OVERWRITE)
    elif dn.exists:
        if not keep:
            w.replace(state, dest, OVERWRITE, backup=backup)
    elif single_file:
        w.write(state, dest, False)
    else:
        w.mkdir(state, dest, False)


# ---- archives -------------------------------------------------------------------

_TAR_OLD_VALUES = "fCTXbKLNVgHIF"


def tar(w, inv, parsed, state, tool) -> None:
    """VERIFIED: tar -x overwrites existing files; -k / --skip-old-files keep
    them. Which files -x writes is in the archive, not on the line: UNKNOWN,
    unless it keeps existing files (creations only) or names its members."""
    from .rules import TAR_OPTIONS
    args = inv.argv[1:]
    if args and not args[0].expands and re.fullmatch(r"[A-Za-z]+", args[0].value):
        letters, rest, new = args[0].value, list(args[1:]), []
        for ch in letters:                           # old style: `tar xzf a.tgz`
            new.append(Word("-" + ch, "-" + ch, args[0].start, args[0].end))
            if ch in _TAR_OLD_VALUES and rest:
                new.append(rest.pop(0))
        parsed = parse_options(new + rest, TAR_OPTIONS)
    f, o = parsed.flags, parsed.options
    archive = [x for x in o.get("file", [])[-1:] if x.value != "-"]
    arch = w.paths(archive, state, inv)
    if "create" in f:
        for p in arch:
            w.write(state, p, False)
        if "remove_files" in f:
            for p in w.paths(parsed.operands, state, inv):
                if w.node(state, p).exists:
                    w.remove(state, p)
        return
    if {"append", "update", "catenate", "concatenate"} & f:
        for p in arch:
            if w.node(state, p).exists:
                w.impact.changes.add(p)
                w.impact.touched.add(p)
            else:
                w.write(state, p, False)
        return
    if "delete" in f:
        for p in arch:
            w.edit(state, p)
        return
    if not ({"extract", "get"} & f) or "to_stdout" in f:
        return
    keep = bool({"keep_old_files", "skip_old_files"} & f)
    cdir = w.paths(o.get("directory", [])[-1:], state, inv)
    here = cdir[0] if cdir else state.cwd
    if parsed.operands and here is not None:
        for m in parsed.operands:
            if m.expands:
                w.impact.not_understood(inv.text, "a tar member named by an expansion")
                continue
            p = os.path.normpath(os.path.join(here, m.value))
            w.create(state, p) if keep else w.write(state, p, False)
        return
    if not keep:
        w.impact.not_understood(inv.text, "tar -x writes whatever the archive holds")


MAX_MEMBERS = 2000


class _Unreadable(Exception):
    pass


def _zip_members(path: str, budget) -> List[Tuple[str, bool, bool, bool]]:
    """(name, is_dir, is_symlink, encrypted) from the central directory only.
    The entry count is read from the end record FIRST, so a huge archive is
    refused before zipfile parses its directory."""
    with budget.paused():
        import struct
        import zipfile
    too_many = _Unreadable(f"the archive lists more than {MAX_MEMBERS:,} members")
    try:
        end_record = getattr(zipfile, "_EndRecData", None)  # private: absent -> count after
        if end_record is not None:
            with open(path, "rb") as fh:
                end = end_record(fh)                     # the end-of-central-directory record
            if not end:
                raise _Unreadable("the archive cannot be read")
            if end[zipfile._ECD_ENTRIES_TOTAL] > MAX_MEMBERS:
                raise too_many
        out = []
        with zipfile.ZipFile(path) as z:
            if len(z.infolist()) > MAX_MEMBERS:
                raise too_many
            for zi in z.infolist():
                budget.check()
                mode = (zi.external_attr >> 16) & 0o170000
                out.append((zi.filename, zi.is_dir(), mode == 0o120000, bool(zi.flag_bits & 0x1)))
        return out
    except _Unreadable:
        raise
    except (zipfile.BadZipFile, OSError, ValueError, NotImplementedError, struct.error):
        raise _Unreadable("the archive cannot be read")


def unzip(w, inv, parsed, state, tool) -> None:
    """VERIFIED: in a shell with no terminal unzip reads EOF at its
    "replace?" prompt and treats it as None - nothing is overwritten. -o
    overwrites, -n never does. Members come from the archive (review ruling 1):
    one that escapes (absolute, or `..`) counts as destroyed OUTSIDE, so the
    verdict is ESCALATE; a symlink member is UNKNOWN.

    -P PASSWORD (I1c, VERIFIED with UnZip 6.0): inside a cluster P takes the
    rest of the word as its value - `-oPsecret` is -o plus the password
    "secret", `-Pxo` is the password "xo" - or the next word when nothing
    follows. With -P an encrypted member is extracted like any other (a wrong
    password only means less is written); without it, with no terminal, unzip
    cannot ask for one, and an encrypted member stays UNKNOWN as before."""
    args = inv.argv[1:]
    opts, exdir, zipword, members, excludes, in_x = set(), None, None, [], [], False
    password = False
    i = 0
    while i < len(args):
        a = args[i]
        v = a.value
        if not a.expands and v.startswith("-") and len(v) > 1:
            if v == "-x":
                in_x = True
            elif v == "-d":
                exdir = args[i + 1] if i + 1 < len(args) else None
                i += 1
                in_x = False
            elif v.startswith("-d"):
                exdir = _sub(a, 2, v[2:])
            elif "P" in v[1:]:
                body = v[1:]
                k = body.index("P")
                opts |= set(body[:k])                    # the letters before P are options
                password = True
                if k == len(body) - 1:
                    i += 1                               # `-P secret`: the next word is it
            else:
                opts |= set(v[1:])
            i += 1
            continue
        if in_x:
            excludes.append(v)
        elif zipword is None:
            zipword = a
        else:
            members.append(v)
        i += 1
    if zipword is None or opts & set("lvtZpcz"):
        return
    found = w.paths([zipword], state, inv)
    if not found:
        return
    zpath = found[0]
    if not w.node(state, zpath).exists and w.node(state, zpath + ".zip").exists:
        zpath += ".zip"
    zn = w.node(state, zpath)
    if not zn.exists:
        return                                          # unzip fails
    if NEW in zn.origins:
        w.impact.not_understood(inv.text, "the archive is written earlier on this line")
        return
    try:
        entries = _zip_members(zpath, w.budget)
    except _Unreadable as u:
        w.impact.not_understood(inv.text, str(u))
        return
    here = w.paths([exdir], state, inv)[0] if exdir is not None else state.cwd
    if here is None:
        w.impact.not_understood(inv.text, "the working directory is unknown")
        return
    over = bool(set("ofu") & opts)
    for name, is_dir, is_link, encrypted in entries:
        w.budget.check()
        if members and not any(fnmatch.fnmatchcase(name, m) for m in members):
            continue
        if any(fnmatch.fnmatchcase(name, x) for x in excludes):
            continue
        if is_link:
            w.impact.not_understood(inv.text, "the archive holds a symbolic link")
            continue
        if encrypted and not password:
            w.impact.not_understood(inv.text, "the archive is encrypted")
            continue
        rel = os.path.basename(name.rstrip("/")) if "j" in opts else name
        parts = rel.replace("\\", "/").split("/")
        if rel.startswith("/") or ".." in parts:
            target = os.path.normpath(rel if rel.startswith("/") else os.path.join(here, rel))
            w.impact.destroy(target, "ZIP_SLIP")
            w.impact.touched.add(target)
            continue
        p = os.path.normpath(os.path.join(here, rel))
        if is_dir:
            w.mkdir(state, p, True)
            continue
        w.mkdir(state, os.path.dirname(p), True)
        n = w.node(state, p)
        if n.exists:
            if not n.is_dir and over:
                w.replace(state, p, OVERWRITE)
        elif "f" not in opts:
            w.create(state, p)


# ---- find -----------------------------------------------------------------------

_FIND_VALUES = frozenset({
    "-name", "-iname", "-path", "-ipath", "-wholename", "-iwholename", "-regex", "-iregex",
    "-type", "-xtype", "-user", "-group", "-perm", "-size", "-mtime", "-mmin", "-atime",
    "-amin", "-ctime", "-cmin", "-newer", "-anewer", "-cnewer", "-samefile", "-links",
    "-inum", "-uid", "-gid", "-maxdepth", "-mindepth", "-fstype", "-context", "-used",
    "-printf", "-regextype", "-lname", "-ilname", "-files0-from"})
_DELETERS = frozenset({"rm", "unlink", "rmdir", "shred"})


def find(w, inv, parsed, state, tool) -> None:
    """-delete and -exec rm {} may remove anything under the starting points
    that the tests match; the tests are not evaluated here, so each starting
    directory is captured whole (WITHIN). find . on the project root is
    therefore ESCALATE, as today."""
    args = inv.argv[1:]
    i = 0
    while i < len(args) and (args[i].value in ("-H", "-L", "-P") or args[i].value.startswith("-O")):
        i += 1
    if i < len(args) and args[i].value == "-D":
        i += 2
    starts = []
    while i < len(args):
        v = args[i].value
        if (v.startswith("-") and len(v) > 1) or v in ("(", "!", ")", ","):
            break
        starts.append(args[i])
        i += 1
    if starts:
        roots = w.paths(starts, state, inv)
    elif state.cwd is not None:
        roots = [state.cwd]
    else:
        w.impact.not_understood(inv.text, "the working directory is unknown")
        return
    expr = args[i:]
    j = 0
    while j < len(expr):
        v = expr[j].value
        if v in ("-exec", "-execdir", "-ok", "-okdir"):
            k = j + 1
            cmd = []
            while k < len(expr) and expr[k].value not in (";", "+"):
                cmd.append(expr[k])
                k += 1
            _find_exec(w, inv, state, cmd, roots)
            j = k + 1
            continue
        if v == "-delete":
            _remove_under(w, state, roots, DELETE)
        elif v in ("-fprint", "-fprint0", "-fls", "-fprintf"):
            if j + 1 < len(expr):
                for p in w.paths([expr[j + 1]], state, inv):
                    w.write(state, p, False)
            j += 3 if v == "-fprintf" else 2
            continue
        elif v in _FIND_VALUES or (v.startswith("-newer") and len(v) == 8):
            j += 2
            continue
        j += 1


def _remove_under(w, state, roots, how) -> None:
    for p in roots:
        n = w.node(state, p)
        if not n.exists:
            continue
        if n.is_dir:
            w.within(state, p, how)
        elif how == DELETE:
            w.remove(state, p)
        else:
            w.edit(state, p)


def _find_exec(w, inv, state, cmd, roots) -> None:
    if not cmd:
        return
    t = os.path.basename(cmd[0].value)
    if t in SHELLS:
        w.impact.not_understood(inv.text, "find runs a shell script for each file")
        return
    if t in READ_ONLY:
        return
    per_file = any("{}" in x.value for x in cmd[1:])
    in_place = any(v.startswith("-") and not v.startswith("--") and "i" in v[1:]
                   or v.startswith("--in-place") for v in (x.value for x in cmd[1:]))
    edits = (t in ("prettier", "eslint", "black", "isort", "rustfmt", "gofmt", "truncate")
             or (t in ("sed", "perl") and in_place))
    if per_file and t in _DELETERS:
        _remove_under(w, state, roots, DELETE)
    elif per_file and edits:
        _remove_under(w, state, roots, OVERWRITE)
    elif t in w.table:
        w.impact.not_understood(inv.text, f"find -exec {t} is not modelled per file")
    else:
        w.impact.not_covered(t)


# ---- Part C2a: SQL clients (engine/sqlclients.py, imported only when met) -----------

def git(w, inv, parsed, state, tool) -> None:
    """git (M2.2a). The implementation is in git_ops.py, imported the first
    time a line names git - outside the budget, like the SQL clients."""
    def load():
        from .git_ops import git as run
        return run
    w.untimed(load)(w, inv, parsed, state, tool)


def infra(w, inv, parsed, state, tool) -> None:
    """terraform / tofu, kubectl, helm, pulumi, cdk (M2.2b1). The
    implementation is in infra_ops.py, imported the first time a line names
    one of them - outside the budget, like git."""
    def load():
        from .infra_ops import infra as run
        return run
    w.untimed(load)(w, inv, parsed, state, tool)


def cloud(w, inv, parsed, state, tool) -> None:
    """aws, s3cmd, rclone, mc (M2.2b2a). The implementation is in cloud_ops.py,
    imported the first time a line names one of them - outside the budget."""
    def load():
        from .cloud_ops import cloud as run
        return run
    w.untimed(load)(w, inv, parsed, state, tool)


def cloud2(w, inv, parsed, state, tool) -> None:
    """gcloud, gsutil, az, azcopy, railway (M2.2b2b), in cloud2_ops.py, imported
    the first time a line names one of them - outside the budget."""
    def load():
        from .cloud2_ops import cloud2 as run
        return run
    w.untimed(load)(w, inv, parsed, state, tool)


def send(w, inv, parsed, state, tool) -> None:
    """HTTP clients, gh, mail, ssh / scp / sftp, package publishing (M2.2b4a),
    in send_ops.py - imported the first time a line names one of them,
    outside the budget."""
    def load():
        from .send_ops import send as run
        return run
    w.untimed(load)(w, inv, parsed, state, tool)


def paas(w, inv, parsed, state, tool) -> None:
    """heroku, fly, vercel, netlify, wrangler, firebase (M2.2b4b1), in
    paas_ops.py - imported the first time a line names one of them."""
    def load():
        from .paas_ops import paas as run
        return run
    w.untimed(load)(w, inv, parsed, state, tool)


def saas(w, inv, parsed, state, tool) -> None:
    """shopify, wp-cli, stripe and the migration tools (M2.2b4b2), in
    saas_ops.py - imported the first time a line names one of them."""
    def load():
        from .saas_ops import saas as run
        return run
    w.untimed(load)(w, inv, parsed, state, tool)


def _send_ops():
    from . import send_ops
    return send_ops


def container(w, inv, parsed, state, tool) -> None:
    """docker, podman, docker-compose (M2.2b3), in container_ops.py, imported
    the first time a line names one of them - outside the budget."""
    def load():
        from .container_ops import container as run
        return run
    w.untimed(load)(w, inv, parsed, state, tool)


def datastore(w, inv, parsed, state, tool) -> None:
    """redis-cli, mongosh / mongo, dropdb / pg_restore / pg_dump, mysqladmin,
    sqlcmd (M2.2b3), in datastore_ops.py - imported outside the budget."""
    def load():
        from .datastore_ops import datastore as run
        return run
    w.untimed(load)(w, inv, parsed, state, tool)


def sql_client(w, inv, parsed, state, tool) -> None:
    def load():
        from . import sql
        from .sqlclients import sql_client as run
        sql.warm({"sqlite3": "sqlite", "psql": "postgres"}.get(tool, "mysql"))
        return run
    w.untimed(load)(w, inv, parsed, state, tool)      # imports stay outside the budget


def system(w, inv, parsed, state, tool) -> None:
    """services, power, processes, accounts, disks, the machine's recovery
    data, network and firewall, modes and owners, the registry (M2.2c), in
    system_ops.py - imported the first time a line names one of them."""
    def load():
        from .system_ops import system as run
        return run
    w.untimed(load)(w, inv, parsed, state, tool)


def vault(w, inv, parsed, state, tool) -> None:
    """The HashiCorp Vault CLI (M2.2f), in vault_ops.py - imported the first
    time a line names it."""
    def load():
        from .vault_ops import vault as run
        return run
    w.untimed(load)(w, inv, parsed, state, tool)
