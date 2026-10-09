"""What leaves the machine (M2.2b4a): HTTP requests (curl, wget, httpie,
xh), GitHub (gh), mail (mail / mailx / sendmail / swaks), remote hosts (ssh,
scp, sftp) and package publishing (npm, pnpm, yarn, cargo, twine, gem,
poetry).

A request, a message, a remote command or a published version cannot be
called back by any local copy, so each is `reach(label, kind)` and policy.py
decides it. Labels: `http:` -> http_api_write, `github:` -> vcs_remote_state,
`mail:` -> external_email, `host:` -> remote_filesystem, `registry:` ->
package_registry, plus the existing `secret:` and `cred:`.

RULINGS (Nizar, 2026-10-07): R6 a request that is not GET / HEAD / OPTIONS is
a change (POST = SEND, PUT / PATCH = OVERWRITE, DELETE = DELETE); R7 a publish
escalates (a version cannot be published twice); R8 scp / sftp to a remote
path = OVERWRITE, `ssh host <cmd>` = RUN, interactive ssh stays with today's
path; R9 a mail sent = SEND.

WHAT IT CLAIMS, AND WHAT IT DOES NOT. Anything not listed is `uncovered`, and
today's text path decides the line unchanged. Not claimed: creations on
GitHub (pr / issue / repo / release create ...: today's path decides, it
escalates some of them), the tools' own login and configuration, installs
(npm install ... keep today's path and its runtime net), interactive ssh /
sftp, and fetch-and-run (`curl ... | sh` is not understood by the shell rule
and stays with today's path).

VERIFIED (2026-10-07), from each tool's own source, help or man pages; no
request was sent:
  - curl 8.18.0 / wget 1.25.0 (--help all): -d / --data* / -F / --json = POST,
    -G = GET, -I = HEAD, -T = PUT (HTTP) or an upload, -X sets the method word;
    wget --method / --post-data / --post-file.
  - httpie 3.2.4 (source): argparse, long options may be abbreviated;
    `http [METHOD] URL [ITEM ...]`; with no METHOD it is POST when stdin is
    not a terminal (--ignore-stdin / -I turns that off) or when an item
    carries data (=, :=, @, =@, :=@), GET otherwise. An agent's shell has no
    terminal on stdin, so a bare `http URL` there is a POST.
  - xh 0.26.2 (source): clap, no abbreviation, a --no-OPTION for every
    option; the same method rule (stdin read when not a terminal).
"""
from __future__ import annotations

import re
from typing import Dict, FrozenSet, List, Optional, Tuple

from ..model import Word
from .cloud_ops import READ, _local, _reach
from .effects import CREATE, DELETE, OVERWRITE, RUN, SEND, SERVICE_LOSS

_READ_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


def _method_kind(method: str) -> str:
    m = method.upper()
    if m in _READ_METHODS:
        return READ
    if m == "DELETE":
        return DELETE
    if m in ("PUT", "PATCH"):
        return OVERWRITE
    return SEND                               # POST and every other method word


def _host(url: str) -> str:
    u = re.sub(r"^[A-Za-z][A-Za-z0-9+.-]*://", "", url)
    u = u.split("/", 1)[0].split("?", 1)[0]
    return (u.rsplit("@", 1)[-1] or "?") if u else "?"


def _scheme(url: str) -> str:
    m = re.match(r"^([A-Za-z][A-Za-z0-9+.-]*)://", url)
    if m:
        return m.group(1).lower()
    return "ftp" if url.lower().startswith("ftp.") else "http"   # VERIFIED: curl's guess


# ---------------------------------------------------------------- curl / wget (network side)

_CURL_DATA = ("data", "data_ascii", "data_binary", "data_raw", "data_urlencode", "json",
              "form", "form_string")
_CURL_UPLOAD_SCHEMES = frozenset({"ftp", "ftps", "sftp", "scp", "smb", "smbs", "tftp", "file"})


def curl_network(w, inv, parsed, state, tool) -> None:
    """The request curl sends, beside the files resolvers.curl writes."""
    f, o = parsed.flags, parsed.options
    urls = list(parsed.operands) + list(o.get("url", []))
    method_words = o.get("request", [])
    if method_words and method_words[-1].expands:
        w.impact.not_understood(inv.text, "the curl method is named by an expansion")
        return
    has_data = any(o.get(k) for k in _CURL_DATA)
    upload = bool(o.get("upload_file"))
    for u in urls:
        if u.expands and not method_words and not has_data and not upload:
            continue                          # an unknown URL, but a plain GET reads
        scheme = "http" if u.expands else _scheme(u.value)
        host = "?" if u.expands else _host(u.value)
        if scheme in ("http", "https"):
            if method_words:
                method = method_words[-1].value
            elif "head" in f:
                method = "HEAD"
            elif "get" in f:
                method = "GET"
            elif has_data:
                method = "POST"
            elif upload:
                method = "PUT"
            else:
                method = "GET"
            _reach(w, inv, f"http:{host}", _method_kind(method), [], tool)
        elif scheme in ("smtp", "smtps"):
            if o.get("mail_rcpt") or upload:
                _reach(w, inv, f"mail:{host}", SEND, [], tool)
        elif scheme == "file":
            if upload or method_words:
                w.impact.not_covered("curl (a file:// upload)")      # a local write, not modelled
            continue
        elif scheme in _CURL_UPLOAD_SCHEMES:
            if upload or method_words:
                _reach(w, inv, f"host:{host}", OVERWRITE, [], tool)
        else:
            w.impact.not_covered(f"curl ({scheme})")


def wget_network(w, inv, parsed, state, tool) -> None:
    o = parsed.options
    method = o.get("method", [])
    if method and method[-1].expands:
        w.impact.not_understood(inv.text, "the wget method is named by an expansion")
        return
    if method:
        m = method[-1].value
    elif o.get("post_data") or o.get("post_file"):
        m = "POST"
    else:
        return                                # GET: a read (the file side is resolvers.wget)
    for u in parsed.operands:
        _reach(w, inv, f"http:{'?' if u.expands else _host(u.value)}", _method_kind(m), [], tool)


# ---------------------------------------------------------------- httpie / xh

_HTTPIE_VALUES = frozenset({
    "--auth", "--auth-type", "--boundary", "--cert", "--cert-key", "--cert-key-pass", "--ciphers",
    "--default-scheme", "--format-options", "--history-print", "--max-headers", "--max-redirects",
    "--output", "--pretty", "--print", "--proxy", "--raw", "--response-charset",
    "--response-mime", "--session", "--session-read-only", "--ssl", "--style", "--timeout",
    "--verify", "-A", "-P", "-a", "-o", "-p", "-s"})
_HTTPIE_FLAGS = frozenset({
    "--all", "--body", "--check-status", "--chunked", "--compress", "--continue", "--debug",
    "--download", "--follow", "--form", "--headers", "--help", "--ignore-netrc", "--ignore-stdin",
    "--json", "--manual", "--meta", "--multipart", "--offline", "--path-as-is", "--quiet",
    "--stream", "--traceback", "--verbose", "--version", "--sorted", "--unsorted", "--no-sorted",
    "--no-unsorted", "-F", "-I", "-S", "-b", "-c", "-d", "-f", "-h", "-j", "-m", "-q", "-v",
    "-x"})
_XH_VALUES = frozenset({
    "--auth", "--auth-type", "--bearer", "--cert", "--cert-key", "--default-scheme",
    "--format-options", "--generate", "--history-print", "--http-version", "--interface",
    "--max-redirects", "--output", "--pretty", "--print", "--proxy", "--raw", "--resolve",
    "--response-charset", "--response-mime", "--session", "--session-read-only", "--ssl",
    "--style", "--timeout", "--unix-socket", "--verify", "-A", "-P", "-a", "-o", "-p", "-s"})
_XH_FLAGS = frozenset({
    "--json", "-j", "--form", "--multipart", "--all", "--body", "--check-status", "--compress", "--continue", "--curl", "--curl-long",
    "--debug", "--download", "--follow", "--form", "--headers", "--help", "--https",
    "--ignore-netrc", "--ignore-stdin", "--json", "--meta", "--multipart", "--native-tls",
    "--offline", "--quiet", "--stream", "--verbose", "-F", "-I", "-S", "-b", "-c", "-d", "-f",
    "-h", "-j", "-m", "-q", "-v", "-x"})
# An item's separator, longest first (httpie cli/constants.py).
_ITEM = re.compile(r"^(?:\\.|[^\\:=@;])*?(:=@|==@|=@|:@|:=|==|=|:|;|@)")
_DATA_SEPS = frozenset({"=", ":=", "@", "=@", ":=@"})


def _long_option(v: str, known: FrozenSet[str], abbrev: bool) -> Optional[str]:
    if v in known:
        return v
    if abbrev and v.startswith("--"):
        hits = [k for k in known if k.startswith(v)]
        if len(hits) == 1:
            return hits[0]
    return None


def _http_like(w, inv, state, tool: str, values: FrozenSet[str], flags: FrozenSet[str],
               abbrev: bool, negations: bool) -> None:
    args = list(inv.argv[1:])
    got: Dict[str, Optional[Word]] = {}
    pos: List[Word] = []
    i, done = 0, False
    while i < len(args):
        a = args[i]
        v = a.value
        if done or a.expands or not v.startswith("-") or v == "-":
            pos.append(a)
            i += 1
            continue
        if v == "--":
            done = True
            i += 1
            continue
        name, eq, glued = v.partition("=")
        if negations and name.startswith("--no-") and ("--" + name[5:]) in (values | flags):
            got.pop("--" + name[5:], None)
            i += 1
            continue
        known = _long_option(name, values | flags, abbrev) if name.startswith("--") else (
            name if name in values | flags else None)
        if known is None and not name.startswith("--") and len(v) > 2:
            # a short cluster: flags, the last may take the rest as a value
            j, ok = 1, True
            while j < len(v):
                s = "-" + v[j]
                if s in flags:
                    got[s] = None
                    j += 1
                    continue
                if s in values:
                    got[s] = Word(a.raw, v[j + 1:], a.start, a.end) if j + 1 < len(v) else (
                        args[i + 1] if i + 1 < len(args) else None)
                    if j + 1 >= len(v):
                        i += 1
                    break
                ok = False
                break
            if not ok:
                return w.impact.not_covered(f"{tool} (option)")
            i += 1
            continue
        if known is None:
            return w.impact.not_covered(f"{tool} (option)")
        if known in values:
            if eq:
                got[known] = Word(a.raw, glued, a.start, a.end, expands=a.expands)
                i += 1
            elif i + 1 < len(args):
                got[known] = args[i + 1]
                i += 2
            else:
                return w.impact.not_covered(f"{tool} (option)")
            continue
        got[known] = None
        i += 1
    if {"--help", "-h", "--version", "--manual"} & set(got):
        return
    if not pos:
        return
    if any(p.expands for p in pos[:2]):
        w.impact.not_understood(inv.text, f"the {tool} method or URL is named by an expansion")
        return
    if len(pos) >= 2 and re.match(r"^[a-zA-Z]+$", pos[0].value):
        method, url, items = pos[0].value, pos[1], pos[2:]       # VERIFIED: httpie / xh rule
    else:
        method, url, items = None, pos[0], pos[1:]
    out = got.get("--output") or got.get("-o")
    if out is not None:
        _local(w, inv, state, out, OVERWRITE, tool)         # the response body
    elif "--download" in got or "-d" in got:
        w.impact.not_understood(inv.text, f"{tool} --download takes the file name from the server")
        return
    if "--offline" in got or "--curl" in got or "--curl-long" in got:
        return                                                  # built and printed, never sent
    if method is None:
        data = any((m := _ITEM.match(x.value)) and m.group(1) in _DATA_SEPS for x in items
                   if not x.expands) or "--raw" in got
        if any(x.expands for x in items):
            w.impact.not_understood(inv.text, f"a {tool} request item named by an expansion")
            return
        stdin = not ({"--ignore-stdin", "-I"} & set(got))
        method = "POST" if (data or stdin) else "GET"
    _reach(w, inv, f"http:{_host(url.value)}", _method_kind(method), [], tool)


# ---------------------------------------------------------------- gh (GitHub CLI 2.102.0)
#
# VERIFIED from gh's own man pages (229 commands, 203 leaves, their flags,
# their aliases). cobra: flags anywhere, `--` ends them, no abbreviation of
# commands or flags, an unknown flag is refused. A word gh does not know as a
# command may be an extension (gh-<name>): uncovered.

_R, _D, _O, _S, _X = READ, DELETE, OVERWRITE, SEND, RUN
# label prefix per group: secrets / variables -> secret:, keys -> cred:, else github:
_GH_KIND = {
    # reads
    **{k: _R for k in (
        "browse", "completion", "licenses", "status", "agent-task list", "agent-task view",
        "alias list", "attestation trusted-root", "attestation verify", "auth status",
        "auth token", "cache list", "codespace list", "codespace logs", "codespace view",
        "config get", "config list", "discussion list", "discussion view", "extension browse",
        "extension list", "extension search", "gist list", "gist view", "gpg-key list",
        "issue list", "issue status", "issue view", "label list", "org list", "pr checks",
        "pr diff", "pr list", "pr status", "pr view", "preview prompter", "project field-list",
        "project item-list", "project list", "project view", "release list", "release verify",
        "release verify-asset", "release view", "repo list", "repo read-dir", "repo read-file",
        "repo view", "repo autolink list", "repo autolink view", "repo deploy-key list",
        "repo gitignore list", "repo gitignore view", "repo license list", "repo license view",
        "ruleset check", "ruleset list", "ruleset view", "run list", "run view", "run watch",
        "search code", "search commits", "search issues", "search prs", "search repos",
        "secret list", "skill list", "skill preview", "skill search", "ssh-key list",
        "variable get", "variable list", "workflow list", "workflow view")},
    # removals
    **{k: _D for k in (
        "cache delete", "codespace delete", "gist delete", "gpg-key delete", "issue delete",
        "label delete", "project delete", "project field-delete", "project item-delete",
        "release delete", "release delete-asset", "repo delete", "repo autolink delete",
        "repo deploy-key delete", "run delete", "secret delete", "ssh-key delete",
        "variable delete")},
    # changes to something that exists
    **{k: _O for k in (
        "codespace edit", "codespace rebuild", "codespace ports visibility", "discussion edit",
        "gist edit", "gist rename", "issue close", "issue edit", "issue lock", "issue pin",
        "issue reopen", "issue transfer", "issue unlock", "issue unpin", "label clone",
        "label edit", "pr close", "pr edit", "pr lock", "pr merge", "pr ready", "pr reopen",
        "pr unlock", "pr update-branch", "project close", "project edit", "project link",
        "project unlink", "project mark-template", "project item-archive", "project item-edit",
        "release edit", "release upload", "repo archive", "repo unarchive", "repo edit", "repo rename",
        "run cancel", "secret set", "variable set", "workflow disable", "workflow enable")},
    # code that runs on GitHub
    **{k: _X for k in ("run rerun", "workflow run")},
    # sent to the world
    "skill publish": _S,
}
_GH_SECRET = ("secret ", "variable ")
_GH_CRED = ("gpg-key ", "ssh-key ", "repo deploy-key ")
_GH_GLOBAL_FLAGS = frozenset({"-h", "--help"})


def _gh_command(args: List[Word], tree) -> Tuple[Optional[str], int]:
    from .send_data import GH_ALIASES
    """(command path, index of its first argument) or (None, i) when the
    command words are not gh's. Flags may stand between command words."""
    path: List[str] = []
    i = 0
    while i < len(args):
        a = args[i]
        if a.expands:
            return None, i
        v = a.value
        if v.startswith("-"):
            return (" ".join(path) or None), i
        cand = " ".join(path + [v])
        cand = GH_ALIASES.get(cand, cand)                 # VERIFIED: gh's own ALIASES
        if cand in tree:
            path = cand.split()
            i += 1
            if not tree[cand]["group"]:
                return cand, i
            continue
        return (" ".join(path) or None) if path else None, i
    return (" ".join(path) or None), i


def _gh_split(words: List[Word], values: FrozenSet[str], flags: FrozenSet[str]
              ) -> Tuple[Optional[List[Word]], Dict[str, List[Word]], Optional[str]]:
    """cobra / pflag: flags anywhere, `--` ends them, `-xVALUE`, `--x=v`, bool
    short clusters. (positionals, flags met, the first unknown flag)."""
    pos: List[Word] = []
    got: Dict[str, List[Word]] = {}
    i, done = 0, False
    while i < len(words):
        a = words[i]
        v = a.value
        if done or a.expands or not v.startswith("-") or v == "-":
            pos.append(a)
            i += 1
            continue
        if v == "--":
            done = True
            i += 1
            continue
        name, eq, glued = v.partition("=")
        if v.startswith("--"):
            if name in values:
                if eq:
                    got.setdefault(name, []).append(Word(a.raw, glued, a.start, a.end, expands=a.expands))
                    i += 1
                elif i + 1 < len(words):
                    got.setdefault(name, []).append(words[i + 1])
                    i += 2
                else:
                    return None, got, name
                continue
            if name in flags:
                got.setdefault(name, [])
                i += 1
                continue
            return None, got, name
        j = 1
        while j < len(v):
            s = "-" + v[j]
            if s in flags:
                got.setdefault(s, [])
                j += 1
                continue
            if s in values:
                rest = v[j + 1:]
                if rest.startswith("="):
                    rest = rest[1:]
                if rest:
                    got.setdefault(s, []).append(Word(a.raw, rest, a.start, a.end, expands=a.expands))
                elif i + 1 < len(words):
                    got.setdefault(s, []).append(words[i + 1])
                    i += 1
                else:
                    return None, got, s
                break
            return None, got, s
        i += 1
    return pos, got, None


def _gh_api(w, inv, pos: List[Word], got, tool: str, where: str) -> None:
    if not pos:
        return w.impact.not_covered("gh api")
    endpoint = pos[0]
    method = (got.get("-X") or got.get("--method") or [None])[-1]
    if method is not None and method.expands:
        w.impact.not_understood(inv.text, "the gh api method is named by an expansion")
        return
    fields = [x for k in ("-f", "-F", "--field", "--raw-field") for x in got.get(k, [])]
    has_body = bool(fields) or bool(got.get("--input"))
    if endpoint.value == "graphql" and not endpoint.expands:
        query = next((x for x in fields if x.value.startswith("query=")), None)
        if query is None or query.expands or query.value.startswith("query=@"):
            w.impact.not_understood(inv.text, "the GraphQL document gh api sends")
            return
        text = query.value[len("query="):].lstrip()
        if text.startswith("mutation"):
            return _reach(w, inv, f"github:{where}", SEND, [], tool)
        if text.startswith(("query", "{")):
            return
        w.impact.not_understood(inv.text, "the GraphQL document gh api sends")
        return
    m = method.value if method is not None else ("POST" if has_body else "GET")
    _reach(w, inv, f"github:{where}", _method_kind(m), [], tool)


def httpie(w, inv, parsed, state, tool) -> None:
    _http_like(w, inv, state, tool, _HTTPIE_VALUES, _HTTPIE_FLAGS, abbrev=True, negations=False)


def xh(w, inv, parsed, state, tool) -> None:
    _http_like(w, inv, state, tool, _XH_VALUES, _XH_FLAGS | {"--multipart", "--form", "--json"},
               abbrev=False, negations=True)


def gh(w, inv, parsed, state, tool) -> None:
    from .send_data import GH_TREE as tree
    args = list(inv.argv[1:])
    if not args or (len(args) == 1 and args[0].value in ("--version", "-h", "--help")):
        return
    cmd, k = _gh_command(args, tree)
    if cmd is None and not args[0].expands and args[0].value.startswith("-"):
        return w.impact.not_covered("gh (option)")              # M2.3b: an option gh's tree lacks
    if cmd is None or tree.get(cmd, {}).get("group"):
        if cmd is not None and any(a.value in ("-h", "--help") for a in args):
            return
        return w.impact.not_covered(f"gh {args[0].value}")
    node = tree[cmd]
    rest = args[k:]
    pos, got, bad = _gh_split(rest, frozenset(node["values"]), frozenset(node["flags"]) | _GH_GLOBAL_FLAGS)
    if bad is not None:
        return w.impact.not_covered(f"gh {cmd} (option)")
    if "-h" in got or "--help" in got:
        return
    repo = (got.get("-R") or got.get("--repo") or [None])[-1]
    where = repo.raw if repo is not None else "current"
    if cmd == "api":
        return _gh_api(w, inv, pos, got, tool, where)
    kind = _GH_KIND.get(cmd)
    if kind is None and cmd in ("pr create", "issue create", "release create"):
        # M2.3b: a pull request, an issue or a release published on the
        # remote (a release may fire deploy workflows) - it kept escalating
        # through the old path; it is a SEND the person sees (ask).
        kind = SEND
    if kind is None:
        return w.impact.not_covered(f"gh {cmd}")
    if cmd == "repo delete" and pos:
        where = pos[0].raw
    if cmd in ("pr close", "pr merge") and ("-d" in got or "--delete-branch" in got):
        kind = DELETE                                  # the branch goes with it
    if cmd == "release upload" and not ("--clobber" in got):
        return w.impact.not_covered("gh release upload")   # adds assets: a creation
    prefix = "secret" if cmd.startswith(_GH_SECRET) else "cred" if cmd.startswith(_GH_CRED) else "github"
    _reach(w, inv, f"{prefix}:{where}", kind, [], tool)


# ---------------------------------------------------------------- mail (ruling R4: claims escalations only)
#
# mail / mailx come in three families (GNU mailutils, bsd-mailx, s-nail)
# whose options differ; sendmail is postfix's / exim's / sendmail's own. Their
# grammars are DOCUMENTATION-ONLY here (verified=False), so - as mysql and
# mysqladmin - only an escalation is claimed: a line that names a recipient
# sends; everything else (reading a mailbox, queue and test modes) is left to
# today's path.

_MAIL_READ_MODES = frozenset({"-f", "-u", "-H", "-e", "-N"})       # read a mailbox / headers
_MAIL_VALUES = frozenset({"-s", "-c", "-b", "-r", "-a", "-A", "-q", "-S", "-T", "-M", "-E"})


def mail(w, inv, parsed, state, tool) -> None:
    args = list(inv.argv[1:])
    rcpt = []
    i = 0
    while i < len(args):
        a = args[i]
        v = a.value
        if a.expands:
            rcpt.append(a)
            i += 1
            continue
        if v == "--":
            rcpt += args[i + 1:]
            break
        if v in _MAIL_READ_MODES or v.startswith(("-f", "-u")):
            return w.impact.not_covered(f"{tool} (a mailbox)")
        if v in _MAIL_VALUES:
            i += 2
            continue
        if v.startswith("-"):
            i += 1
            continue
        rcpt.append(a)
        i += 1
    if rcpt:
        _reach(w, inv, f"mail:{rcpt[0].raw}", SEND, [], tool)
    else:
        w.impact.not_covered(tool)


def sendmail(w, inv, parsed, state, tool) -> None:
    args = list(inv.argv[1:])
    for a in args:
        if a.value.startswith("-b") and not a.expands:
            mode = a.value[2:3]
            if mode not in ("m", "s", ""):              # -bm deliver (the default), -bs SMTP on stdin
                return w.impact.not_covered(f"sendmail -b{mode}")
        if a.value.startswith("-q") and not a.expands:
            return w.impact.not_covered("sendmail -q")
    _reach(w, inv, "mail:sendmail", SEND, [], tool)


def swaks(w, inv, parsed, state, tool) -> None:
    args = [a.value for a in inv.argv[1:]]
    if any(v in ("--help", "-h", "--version") for v in args):
        return
    if any(v.startswith(("-q", "--q", "--quit")) for v in args):
        return w.impact.not_covered("swaks --quit-after")    # stops before the message
    _reach(w, inv, "mail:swaks", SEND, [], tool)


# ---------------------------------------------------------------- ssh / scp / sftp (OpenSSH 10.2p1)
#
# VERIFIED from OpenSSH 10.2p1's source and the installed binary (ssh -G,
# which prints the configuration and connects nowhere): OpenSSH's own BSD
# getopt stops at the first word that is not an option; ssh then reads
# options AGAIN after the destination (`ssh host -v cmd`), stops at the first
# command word, and `--` ends them. scp stops at its first operand.

_SSH_VALUES = "BbcDEeFIiJLlmOoPpQRSWw"
_SSH_FLAGS = "46AaCfGgKkMNnqsTtVvXxYy"
_SCP_VALUES = "cDFiJlMoPSX"
_SCP_FLAGS = "12346ABCTdfOpqRrstv"


def _bsd_getopt(words: List[Word], values: str, flags: str
                ) -> Tuple[Dict[str, List[Word]], List[Word], Optional[str]]:
    """(options met, the rest from the first non-option, the first unknown)."""
    opts: Dict[str, List[Word]] = {}
    i = 0
    while i < len(words):
        a = words[i]
        v = a.value
        if a.expands or not v.startswith("-") or v == "-":
            break
        if v == "--":
            i += 1
            break
        j = 1
        while j < len(v):
            ch = v[j]
            if ch in flags:
                opts.setdefault("-" + ch, [])
                j += 1
                continue
            if ch in values:
                if j + 1 < len(v):
                    opts.setdefault("-" + ch, []).append(Word(a.raw, v[j + 1:], a.start, a.end))
                elif i + 1 < len(words):
                    opts.setdefault("-" + ch, []).append(words[i + 1])
                    i += 1
                else:
                    return opts, [], "-" + ch
                break
            return opts, words[i:], "-" + ch
        i += 1
    return opts, words[i:], None


_STDIN_OPS = frozenset({"<", "<<", "<<-", "<<<", "<&", "<>"})


def _stdin_fed(w, inv) -> bool:
    """Whether the line feeds this command's stdin: a pipe (simulate's
    `upstream`), a heredoc, or an input redirect on fd 0."""
    if w.upstream is not None or inv.heredocs:
        return True
    return any(r.op in _STDIN_OPS and (r.fd or "0") == "0" for r in inv.redirects)


def ssh(w, inv, parsed, state, tool) -> None:
    opts, rest, bad = _bsd_getopt(list(inv.argv[1:]), _SSH_VALUES, _SSH_FLAGS)
    if bad is not None:
        return w.impact.not_covered("ssh (option)")
    if {"-G", "-V", "-Q"} & set(opts):
        return                                              # prints, connects nowhere
    if not rest:
        return w.impact.not_covered("ssh")
    dest = rest[0]
    if dest.expands:
        w.impact.not_understood(inv.text, "the ssh destination is named by an expansion")
        return
    more, cmd, bad = _bsd_getopt(list(rest[1:]), _SSH_VALUES, _SSH_FLAGS)   # options after the host
    if bad is not None:
        return w.impact.not_covered("ssh (option)")
    opts.update(more)
    if {"-G", "-V", "-Q"} & set(opts):
        return
    if {"-N", "-O", "-W"} & set(opts):
        return w.impact.not_covered("ssh (a tunnel or a control command)")
    label = "host:" + _host(dest.value).split(":")[0]
    if cmd:
        return _reach(w, inv, label, RUN, [], tool)          # ruling R8: an unread remote command
    if _stdin_fed(w, inv):
        return _reach(w, inv, label, RUN, [], tool)          # the remote shell reads the commands
    w.impact.not_covered("ssh (interactive)")


_REMOTE = re.compile(r"^(?:scp://|(?:[^/:@]+@)?(?:\[[^\]]+\]|[^/:]+):)")


def _is_remote(word: Word) -> bool:
    v = word.value
    if re.match(r"^[A-Za-z]:[\\/]", v):
        return False                                        # a Windows drive, not a host
    return bool(_REMOTE.match(v))


def scp(w, inv, parsed, state, tool) -> None:
    opts, operands, bad = _bsd_getopt(list(inv.argv[1:]), _SCP_VALUES, _SCP_FLAGS)
    if bad is not None:
        return w.impact.not_covered("scp (option)")
    if len(operands) < 2:
        return w.impact.not_covered("scp")
    if any(o.expands for o in operands):
        w.impact.not_understood(inv.text, "an scp operand is named by an expansion")
        return
    *sources, target = operands
    if _is_remote(target):
        host = _host(target.value.replace("scp://", "")).split(":")[0]
        return _reach(w, inv, f"host:{host}", OVERWRITE, [], tool)
    if not any(_is_remote(s) for s in sources):
        return w.impact.not_covered("scp (a local copy)")
    _local(w, inv, state, target, OVERWRITE, tool, whole="-r" in opts or len(sources) > 1)


_SFTP_VALUES = "BbcDFiJlMoPRSsX"
_SFTP_FLAGS = "1246AafhNpqrv"


def sftp(w, inv, parsed, state, tool) -> None:
    opts, operands, bad = _bsd_getopt(list(inv.argv[1:]), _SFTP_VALUES, _SFTP_FLAGS)
    if bad is not None or not operands:
        return w.impact.not_covered("sftp")
    if operands[0].expands:
        w.impact.not_understood(inv.text, "the sftp destination is named by an expansion")
        return
    if "-b" in opts or _stdin_fed(w, inv):
        host = _host(operands[0].value).split(":")[0]
        return _reach(w, inv, f"host:{host}", OVERWRITE, [], tool)   # unread put / rm commands
    w.impact.not_covered("sftp (interactive)")


# ---------------------------------------------------------------- npm (10.9.7 and 12.2.0)
#
# VERIFIED from npm's own source, both majors in use (10.9.7 installed here,
# 12.2.0 the current release): the command is the first positional after
# nopt has read the options; npm resolves it as lib/utils/cmd-list.js deref()
# does (camelCase -> kebab, exact, alias, unique abbreviation, alias again).
# nopt: options anywhere, `--` ends them, `--k=v` never takes the next word,
# long names may be abbreviated, `no-` toggles a boolean, an unknown name is a
# boolean, a boolean takes a following `true` / `false`, a String takes the
# next word unless it looks like an option, other value types take it. The
# two majors' command lists, aliases and option types differ (npm_data), so a
# word counts only when both majors read it the same way; anything else -
# shorthands (-x) before the command included - is left to today's path.

def _npm_deref(c: str, major: str) -> Optional[str]:
    from .send_data import NPM
    commands, aliases = NPM[major]["commands"], NPM[major]["aliases"]
    if re.search(r"[A-Z]", c):
        c = re.sub(r"([A-Z])", lambda m: "-" + m.group(1).lower(), c)
    if c in commands:
        return c
    if c in aliases:
        return aliases[c]
    names = sorted(set(commands) | set(aliases))
    hits = [n for n in names if n.startswith(c)]
    a = c if c in names else (hits[0] if len(hits) == 1 else None)
    while a in aliases:
        a = aliases[a]
    return a


def _npm_option(name: str, major: str) -> Tuple[Optional[str], str]:
    """(key, class) as nopt reads `--name`; class in bool / string / other /
    complex / unknown."""
    from .send_data import NPM
    types = NPM[major]["types"]
    if name in types:
        return name, types[name]
    hits = [k for k in types if k.startswith(name)]
    if len(hits) == 1:
        return hits[0], types[hits[0]]
    return None, "unknown"


def _npm_read(args: List[Word], major: str):
    """(positionals, {key: value or True/False}, certain) as nopt reads them."""
    pos: List[Word] = []
    got: Dict[str, object] = {}
    i = 0
    while i < len(args):
        a = args[i]
        v = a.value
        if a.expands:
            return pos, got, False
        if re.fullmatch(r"-{2,}", v):
            pos += args[i + 1:]
            break
        if not v.startswith("-") or v == "-":
            pos.append(a)
            i += 1
            continue
        if not v.startswith("--"):
            return pos, got, False                       # a shorthand: not modelled
        name, eq, glued = v[2:].partition("=")
        no = False
        while name.lower().startswith("no-"):
            no, name = not no, name[3:]
        key, cls = _npm_option(name, major)
        nxt = args[i + 1].value if i + 1 < len(args) and not args[i + 1].expands else None
        if eq:
            got[key or name] = glued if not no else False
            i += 1
            continue
        if cls == "complex":
            return pos, got, False
        if no or cls in ("bool", "unknown"):
            val: object = not no
            if nxt in ("true", "false"):
                val = (nxt == "true") != no
                i += 1
            got[key or name] = val
            i += 1
            continue
        if cls == "string":
            if nxt is None or re.match(r"^-{1,2}[^-]+", nxt):
                got[key] = ""
                i += 1
            else:
                got[key] = nxt
                i += 2
            continue
        # other value types (url, path, Number ...)
        if nxt is None or re.fullmatch(r"-{2,}", nxt):
            got[key] = True
            i += 1
        else:
            got[key] = nxt
            i += 2
    return pos, got, True


_NPM_KIND = {"publish": SEND, "unpublish": DELETE, "deprecate": OVERWRITE,
             "undeprecate": OVERWRITE}
_NPM_SUB = {"dist-tag": {"add": OVERWRITE, "set": OVERWRITE, "rm": DELETE, "ls": READ, "list": READ},
            "owner": {"add": OVERWRITE, "rm": DELETE, "ls": READ, "list": READ},
            "access": {"grant": OVERWRITE, "revoke": OVERWRITE, "set": OVERWRITE,
                       "get": READ, "list": READ},
            "stage": {"publish": SEND, "approve": SEND, "reject": DELETE,
                      "list": READ, "view": READ, "download": READ},
            "trust": {"github": OVERWRITE, "gitlab": OVERWRITE, "circleci": OVERWRITE,
                      "revoke": DELETE, "list": READ}}


def _npm_kind(args: List[Word], major: str) -> Tuple[Optional[str], Optional[str]]:
    """(the command npm `major` runs, the kind it has here), or (None, None)
    when the command word itself is not certain."""
    pos, got, certain = _npm_read(args, major)
    if not pos or pos[0].expands:
        return None, None
    cmd = _npm_deref(pos[0].value, major)
    if cmd in _NPM_SUB:
        sub = pos[1].value if len(pos) > 1 and not pos[1].expands else ""
        kind = _NPM_SUB[cmd].get(sub)
    else:
        kind = _NPM_KIND.get(cmd or "")
    if kind in (SEND, OVERWRITE, DELETE) and certain and got.get("dry-run") is True:
        kind = READ                                      # VERIFIED: nothing reaches the registry
    return cmd, kind


def npm(w, inv, parsed, state, tool) -> None:
    """A registry write on EITHER major escalates; a read needs both majors
    to agree. Every other command keeps today's path (installs, scripts ...)."""
    args = list(inv.argv[1:])
    kinds = [_npm_kind(args, major)[1] for major in ("10", "12")]
    writes = [k for k in kinds if k in (SEND, OVERWRITE, DELETE)]
    if writes:
        return _reach(w, inv, "registry:npm", writes[0], [], tool)
    if kinds == [READ, READ]:
        return
    w.impact.not_covered("npm")


# ---------------------------------------------------------------- pnpm / yarn (ruling R4: escalations only)

def pnpm_yarn(w, inv, parsed, state, tool) -> None:
    """Documentation-only grammar here: `<tool> publish` (yarn berry: `yarn npm
    publish`) with no option before it is claimed as a publish; nothing that
    would allow is claimed."""
    args = list(inv.argv[1:])
    words = [a.value for a in args[:2] if not a.expands]
    if words[:1] == ["publish"] or (tool == "yarn" and words[:2] == ["npm", "publish"]):
        return _reach(w, inv, f"registry:{tool}", SEND, [], tool)
    if words[:1] == ["unpublish"] or (tool == "yarn" and words[:2] == ["npm", "unpublish"]):
        return _reach(w, inv, f"registry:{tool}", DELETE, [], tool)
    w.impact.not_covered(tool)


# ---------------------------------------------------------------- cargo (0.100.0)
#
# VERIFIED from cargo's source: global options before the subcommand; a
# built-in command always wins over a user alias; anything else may be a
# user alias or an external cargo-<name> (uncovered). rustup's `+toolchain`
# first word is the proxy's, not cargo's.

_CARGO_GLOBAL_VALUES = frozenset({"--color", "-C", "--config", "-Z", "--explain"})
_CARGO_GLOBAL_FLAGS = frozenset({"-V", "--version", "--list", "-v", "--verbose", "-vv", "-q",
                                 "--quiet", "--locked", "--offline", "--frozen", "-h", "--help"})


def cargo(w, inv, parsed, state, tool) -> None:
    args = list(inv.argv[1:])
    if args and args[0].value.startswith("+") and not args[0].expands:
        args = args[1:]
    i = 0
    while i < len(args):
        a = args[i]
        v = a.value
        if a.expands:
            return w.impact.not_covered("cargo")
        if not v.startswith("-"):
            break
        name = v.split("=", 1)[0]
        if name in _CARGO_GLOBAL_VALUES:
            i += 1 if "=" in v else 2
            continue
        if name in _CARGO_GLOBAL_FLAGS or re.fullmatch(r"-v+", v):
            i += 1
            continue
        return w.impact.not_covered("cargo (option)")
    if i >= len(args):
        return
    sub, rest = args[i].value, [a.value for a in args[i + 1:]]
    if "-h" in rest or "--help" in rest:
        return
    if sub == "publish":
        if "--dry-run" in rest or any(re.fullmatch(r"-[nvq]*n[nvq]*", x) for x in rest):
            return                                       # VERIFIED: -n / --dry-run uploads nothing
        return _reach(w, inv, "registry:crates", SEND, [], tool)
    if sub == "yank":
        return _reach(w, inv, "registry:crates", OVERWRITE if "--undo" in rest else DELETE, [], tool)
    if sub == "owner":
        if any(x.startswith(("-a", "-r", "--add", "--remove")) for x in rest):
            return _reach(w, inv, "registry:crates", OVERWRITE, [], tool)
        return
    w.impact.not_covered(f"cargo {sub}")


# ---------------------------------------------------------------- twine (7.0.0)

def twine(w, inv, parsed, state, tool) -> None:
    """VERIFIED (source): `twine [--version] [--no-color] COMMAND ...`; COMMAND
    is an exact argparse choice (no abbreviation); upload and register send,
    with no dry-run; check reads."""
    args = list(inv.argv[1:])
    i = 0
    while i < len(args) and args[i].value in ("--no-color", "--version", "-h", "--help"):
        if args[i].value != "--no-color":
            return
        i += 1
    if i >= len(args) or args[i].expands:
        return w.impact.not_covered("twine")
    sub, rest = args[i].value, [a.value for a in args[i + 1:]]
    if "-h" in rest or any(x.startswith("--h") and "--help".startswith(x) and len(x) >= 3 for x in rest):
        return
    if sub in ("upload", "register"):
        return _reach(w, inv, "registry:pypi", SEND, [], tool)
    if sub == "check":
        return
    w.impact.not_covered(f"twine {sub}")


# ---------------------------------------------------------------- gem (RubyGems 4.0.22)

_GEM_BUILTIN = ("build", "cert", "check", "cleanup", "contents", "dependency", "environment",
                "exec", "fetch", "generate_index", "help", "info", "install", "list", "lock",
                "mirror", "open", "outdated", "owner", "pristine", "push", "rdoc", "rebuild",
                "search", "server", "signin", "signout", "sources", "specification", "stale",
                "uninstall", "unpack", "update", "which", "yank")
_GEM_ALIASES = {"i": "install", "login": "signin", "logout": "signout"}


def gem(w, inv, parsed, state, tool) -> None:
    """VERIFIED (source): before the command only -h / -v / -C DIR; the
    command is an alias, an exact name, or a unique prefix (an ambiguous one
    is an error). Plugins can only make a prefix ambiguous."""
    args = list(inv.argv[1:])
    if args and args[0].value == "-C" and len(args) > 2:
        args = args[2:]
    if not args or args[0].expands or args[0].value.startswith("-"):
        return w.impact.not_covered("gem")
    c = _GEM_ALIASES.get(args[0].value, args[0].value)
    hits = [n for n in _GEM_BUILTIN if n.startswith(c)]
    cmd = c if c in _GEM_BUILTIN else (hits[0] if len(hits) == 1 else None)
    rest = [a.value for a in args[1:]]
    if "-h" in rest or "--help" in rest:
        return
    if cmd == "push":
        return _reach(w, inv, "registry:rubygems", SEND, [], tool)
    if cmd == "yank":
        return _reach(w, inv, "registry:rubygems", DELETE, [], tool)
    if cmd == "owner":
        if all(not x.startswith("-") for x in rest):
            return                                       # lists the owners
        return _reach(w, inv, "registry:rubygems", OVERWRITE, [], tool)   # -a / -r, or unsure
    w.impact.not_covered(f"gem {args[0].value}")


# ---------------------------------------------------------------- poetry (2.5.1, cleo 2.1.0)

_POETRY_GLOBAL_VALUES = frozenset({"-C", "--directory", "-P", "--project"})
_POETRY_GLOBAL_FLAGS = frozenset({"-q", "--quiet", "-v", "-vv", "-vvv", "--verbose", "-n",
                                  "--no-interaction", "--ansi", "--no-ansi", "--no-plugins",
                                  "--no-cache", "-V", "--version", "-h", "--help"})


def poetry(w, inv, parsed, state, tool) -> None:
    """VERIFIED (source): cleo 2.1.0 does not abbreviate commands; `publish
    --dry-run` uploads nothing; a value option cannot take `--dry-run` (it
    starts with '-')."""
    args = list(inv.argv[1:])
    i = 0
    while i < len(args):
        a = args[i]
        v = a.value
        if a.expands:
            return w.impact.not_covered("poetry")
        if not v.startswith("-"):
            break
        name = v.split("=", 1)[0]
        if name in _POETRY_GLOBAL_VALUES:
            i += 1 if "=" in v else 2
            continue
        if name in _POETRY_GLOBAL_FLAGS:
            if name in ("-V", "--version", "-h", "--help"):
                return
            i += 1
            continue
        return w.impact.not_covered("poetry (option)")
    if i >= len(args):
        return
    sub, rest = args[i].value, [a.value for a in args[i + 1:]]
    if sub != "publish":
        return w.impact.not_covered(f"poetry {sub}")
    if "-h" in rest or "--help" in rest:
        return
    rest = rest[:rest.index("--")] if "--" in rest else rest
    if "--dry-run" in rest:
        if "--build" in rest:
            return w.impact.not_covered("poetry publish --build")   # it writes dist/
        return
    _reach(w, inv, "registry:pypi", SEND, [], tool)


# ---------------------------------------------------------------- entry

_TOOLS = {"http": httpie, "https": httpie, "xh": xh, "xhs": xh, "gh": gh, "mail": mail,
          "mailx": mail, "sendmail": sendmail, "swaks": swaks, "ssh": ssh, "scp": scp,
          "sftp": sftp, "npm": npm, "pnpm": pnpm_yarn, "yarn": pnpm_yarn, "cargo": cargo,
          "twine": twine, "gem": gem, "poetry": poetry}


def send(w, inv, parsed, state, tool) -> None:
    _TOOLS[tool](w, inv, parsed, state, tool)
