"""One policy: what a change to a surface no local copy can restore gets,
which surface an engine label names, and where a person can restore it from.

decide.py, engine/verdict.py, guard.py and protection.py read this module and
nothing else for these answers. Change a decision or a hint HERE, once."""
from .engine.effects import (CREATE, DELETE, LATER, OVERWRITE, REF, RUN, SEND,
                             SERVICE_KEEP, SERVICE_LOSS)

ALLOW, ESCALATE = "ALLOW", "ESCALATE"

# Ruling Q1 (C2 review): a remote change that can lose data or cannot be
# recalled escalates; one that only adds, or restores availability, is
# allowed and listed in the receipt.
REMOTE_POLICY = {
    DELETE: ESCALATE, OVERWRITE: ESCALATE, SEND: ESCALATE, RUN: ESCALATE,
    SERVICE_LOSS: ESCALATE, SERVICE_KEEP: ALLOW, CREATE: ALLOW,
    # M2.2a, ruling (c): a history move a reflog entry brings back is allowed
    # and listed in the receipt. The commands that destroy the reflog itself
    # carry DELETE or OVERWRITE instead, and escalate with the rest.
    REF: ALLOW,
    # M2.2d, ruling D1: code planted where it runs later, unseen - a person
    # sees the exact file or command (ask channel: deferred_execution)
    LATER: ESCALATE,
}

def remote_decision(kind: str) -> str:
    """An unknown kind escalates."""
    return REMOTE_POLICY.get(kind, ESCALATE)

# Engine remote labels -> surface. The receipt and the gate key `surface`
# read these names; they are unchanged from guard._engine_facts.
_LABEL_SURFACES = (("db:", "remote_database"), ("device:", "disk_format"),
                   ("vcs-remote:", "remote_vcs_history"),
                   ("vcs-local:", "local_vcs_history"),
                   # M2.2b1: infrastructure CLIs
                   ("iac:", "infra_destroy"), ("cluster:", "cluster_resource_delete"),
                   ("cluster-workload:", "cluster_availability"),
                   # M2.2b2a: cloud CLIs and object stores
                   ("storage:", "object_storage"), ("cred:", "credential_rotation"),
                   ("secret:", "secret_write"), ("queue:", "message_queue"),
                   ("cloud:", "cloud_resource_delete"),
                   # M2.2b2b: railway volumes keep the surface the old rule gave them
                   ("volume:", "remote_volume"),
                   # M2.2b3: containers keep the surface the old rules gave them;
                   # a whole keyspace emptied keeps datastore_flush
                   ("container:", "container_runtime"), ("flush:", "datastore_flush"),
                   # M2.2b4a: what leaves the machine keeps the surfaces the old
                   # rules gave it
                   ("http:", "http_api_write"), ("github:", "vcs_remote_state"),
                   ("mail:", "external_email"), ("host:", "remote_filesystem"),
                   ("registry:", "package_registry"),
                   # M2.2b4b1: PaaS CLIs keep the surfaces the old rules gave them
                   ("paas:", "paas_destroy"), ("deploy:", "saas_deploy"),
                   # M2.2b4b2: stores, CMS, payments, migrations
                   ("cms:", "saas_cms"), ("payment:", "external_payment"),
                   ("migration:", "schema_migration"),
                   # M2.2c: this machine - services, power, processes, accounts,
                   # its recovery data, network, owners, the registry
                   ("service:", "service_control"), ("power:", "host_power"),
                   ("process:", "process_control"), ("account:", "account_control"),
                   ("sysrec:", "system_recovery"), ("net:", "host_network"),
                   ("owner:", "file_ownership"), ("winreg:", "system_config"),
                   # M2.2d: code that runs later
                   ("later:", "deferred_execution"))

def surface_of(label: str) -> str:
    return next((s for p, s in _LABEL_SURFACES if label.startswith(p)), "remote_surface")

# Approach B: where the PROVIDER keeps its own history. Destinations only,
# no UI steps or URLs (those go stale).
RECOVERY_HINTS = {
    "saas_deploy": "deploy rollback / previous theme version",
    "saas_cms": "page/post version history or trash",
    "paas_destroy": "DB backups (PITR) or release rollback",
    "object_storage": "bucket versioning, if enabled",
    "remote_database": "the database's PITR / snapshot",
    "vcs_remote_state": "branch/tag protection or a fresh clone's reflog",
    "external_payment": "the provider dashboard (refund/void) - not always possible",
    "schema_migration": "the migration tool's downgrade",
    "remote_vcs_history": "a teammate's un-force-pushed clone or the remote's reflog",
    "http_api_write": "the API's own trash / restore endpoint, if it has one - often none",
    "service_control": "the service's original definition (sc qc / Get-Service), if anyone captured it",
    "account_control": "the account must be recreated by hand; its SID and grants do not come back",
    "container_runtime": "rebuild from the Dockerfile / compose file, or a volume backup if one exists",
    "datastore_flush": "the instance's own RDB or AOF snapshot, if persistence was enabled - otherwise none",
    "package_registry": "the registry's restore window, if any - npm forbids re-publishing the same version",
    "disk_format": "block-device restore / disk image backup",
    "remote_surface": "its version history / rollback",
    # added in T5 (A2.2): every surface a producer can emit has a hint
    "infra_destroy": ("the Terraform state backend's version history, then re-apply"
                      " (Pulumi: the stack's checkpoints; cdk: the CloudFormation stack)"),
    "cluster_resource_delete": "the manifests in version control, or a cluster backup (Velero / etcd snapshot)",
    "cloud_resource_delete": "the provider's snapshots or backups of that resource, if any were taken",
    "remote_volume": "the platform's volume backups, if enabled",
    "external_email": "none - a sent message cannot be recalled",
    "external_message": "none - a posted message can be deleted, not unsent",
    "credential_rotation": "the provider's previous key version, if it keeps one",
    "secret_write": "the secret store's version history (Secrets Manager / Vault KV versions)",
    "message_queue": "none - purged messages are gone unless the producer can replay them",
    "remote_filesystem": "the remote host's own backups",
    "recursive_force_delete": "an independent backup only - the recycle bin is bypassed",
    "managed_database": "the provider's PITR / snapshot",
    # M2.2a: .git is never snapshotted, so the repository's own history is
    # where these come back from - when anything still holds them.
    "local_vcs_history": "git reflog, or the dangling objects git fsck lists - neither survives a prune",
    # M2.2b1: scale, drain, cordon, rollout restart - nothing is deleted;
    # what changes is how much of the workload is running
    "cluster_availability": "scale the workload to its previous replica count, uncordon the node, or roll the deployment back",
    # M2.2c: this machine
    "host_power": "nothing to restore - start the machine and its services again; unsaved work is gone",
    "process_control": "start the process again; what it held only in memory is gone",
    "system_recovery": "none on this machine - the shadow copies, backups, boot settings or event log it removed are what a recovery would have used",
    "host_network": "the rules or settings saved before the change (iptables-save, nft list ruleset, netsh advfirewall export), if any were saved",
    "file_ownership": "set the owner and ACL back by hand (chown, or icacls /restore from a saved ACL file)",
    "system_config": "a `reg export` of the key taken before the change, if one exists",
    # M2.2d
    "deferred_execution": "remove what was planted (the startup-file lines, the hook, the cron or scheduled job, the unit) before it runs",
}
GENERIC_HINT = "its version history / rollback"

def recovery_hint(surface) -> str:
    return RECOVERY_HINTS.get(surface or "", GENERIC_HINT)



# THE ASK CHANNEL (queue item 8; Nizar's table, 2026-10-07). An escalation
# stays ESCALATE - the gate and every decision are unchanged. What this adds
# is whether a PERSON may approve it on the spot: ASK where the change is real
# but ordinary and the exact command tells the person what they are agreeing
# to; DENY where the whole thing goes with no realistic way back, so only the
# structural approval token or running it outside the agent gets it through.
# A surface with no row here is DENY: a new surface never asks by accident.
# Each door turns this into what it can actually show (hooks/claude_code.py:
# a permission prompt in the modes that show one; Codex: deny, its runtime
# has no ask; the shell guard: a terminal prompt in an interactive shell).
ASK, DENY = "ask", "deny"
ESCALATION_CHANNEL = {
    # ordinary changes a person can judge from the command
    "remote_database": ASK, "managed_database": ASK, "container_runtime": ASK,
    "remote_vcs_history": ASK, "local_vcs_history": ASK, "vcs_remote_state": ASK,
    "cluster_resource_delete": ASK, "cluster_availability": ASK,
    "object_storage": ASK, "cloud_resource_delete": ASK, "remote_volume": ASK,
    "secret_write": ASK, "credential_rotation": ASK, "http_api_write": ASK,
    "package_registry": ASK, "schema_migration": ASK, "saas_deploy": ASK,
    "saas_cms": ASK, "service_control": ASK, "remote_filesystem": ASK,
    "external_message": ASK, "external_email": ASK, "remote_surface": ASK,
    # M2.2c (rulings C2, C3, C7, C8, C9)
    "host_power": ASK, "process_control": ASK, "host_network": ASK,
    "file_ownership": ASK, "system_config": ASK,
    # M2.2d (ruling D1)
    "deferred_execution": ASK,
    # the whole thing gone, no realistic undo
    "datastore_flush": DENY, "disk_format": DENY, "infra_destroy": DENY,
    "recursive_force_delete": DENY, "account_control": DENY, "message_queue": DENY,
    "external_payment": DENY, "paas_destroy": DENY,
    "system_recovery": DENY,     # M2.2c, ruling C6
}
# Escalations that name no surface (decide.py's other branches).
NO_SURFACE_CHANNEL = {
    "local_no_recovery": ASK,    # a local change nothing could capture
    "context_mismatch": ASK,     # the declared context disagrees, nothing captured
    "remote_exec": DENY,         # fetch-and-run: nobody can see the payload first
}
# A target DECLARED in one of these environments (.demo_cli.toml or
# --actual-env - never guessed from the command's words) is shown to a person
# even when a recovery point was captured, and an escalation on it is never
# approvable on the spot.
CONFIRM_ENVIRONMENTS = frozenset({"production"})


def may_ask(surface) -> bool:
    """Whether a person may approve an escalation on `surface` on the spot."""
    return ESCALATION_CHANNEL.get(surface or "", DENY) == ASK



# M2.3 (rulings M1-M5, Nizar, 2026-10-08): what a POSIX line the engine does
# not fully read gets, now that the old text rules no longer decide it.
#
# CODE RUNNERS run code this engine does not read (a script, `-c` / `-e`
# text, a project's scripts). The engine reports them `uncovered` by the
# words below (the first word of each `uncovered` entry), or as a program
# started by path (`./x.sh`). They go to the runtime net (SUPERVISED), else
# a checkpoint, else they are ALLOWED with an honest note: nothing was
# captured, nothing watched (M1).
CODE_RUNNERS = frozenset({
    "python", "python3", "py", "node", "ruby", "perl", "bash", "sh", "zsh", "dash", "ksh",
    "make", "gmake", "npm", "yarn", "pnpm", "npx", "pytest", "jest", "cargo", "go", "java",
    "deno", "bun", "uv", "poetry", "tox", "pip", "pip3", "pipx", "gem", "bundle",
    "apt", "apt-get", "brew", "dnf", "yum", "pacman",
    "awk", "gawk", "mawk", "nawk",          # a program that writes or runs (engine/resolvers.awk)
    "source", ".",                          # a script run in the current shell
})
# A line the engine marks NOT UNDERSTOOD goes to the runtime net, else a
# checkpoint, else it ESCALATES (M3). Any other word with no rule has no
# effect (the floor). A POSIX line that NAMES a PowerShell or cmd.exe word
# keeps the old rules (M5). Since C3 this list no longer touches a line in the
# PowerShell dialect: the engine reads those (ruling PS6).
OLD_RULES_KEEP = frozenset({
    "powershell", "pwsh", "cmd", "Remove-Item", "REMOVE-ITEM", "ri", "del", "erase", "rd",
    "Clear-Content", "clc", "Set-Content", "Out-File", "Move-Item", "mi", "move", "Copy-Item",
    "cpi", "copy", "Rename-Item", "ren", "rni", "New-Item", "ni", "Stop-Service", "spsv",
    "Remove-Service", "Set-Service", "New-Service", "Restart-Service", "Start-Service",
    "Get-Item", "Get-Service", "gsv", "Select-Object", "Format-List", "Format-Volume",
    "Clear-Disk",
})

# A line demo_cli cannot read that reaches past local files - a cloud /
# cluster / container / service / SaaS call, or a download feeding what runs
# - gets neither the net nor a checkpoint: both see this project only (V18).
# It ESCALATES. The downloaders: what they fetch is code or data nobody read.
FETCHERS = frozenset({"curl", "wget"})
# Remote-family calls whose unread part only rewrites local files: the net
# and a checkpoint DO see those (`terraform fmt -recursive`).
LOCAL_UNREAD = frozenset({("terraform", "fmt"), ("tofu", "fmt")})

# Rb2 (M2.3b, Nizar 2026-10-09): runners that, with NO runtime net, escalate
# instead of ALLOW + note. With the net they are SUPERVISED like every runner.
# Inline code (the value of the option) that names a call starting other
# programs - its effects are other programs' nobody read:
INLINE_SPAWNS = {
    "python": (("-c",), ("os.system", "os.popen", "subprocess", "pty.spawn", "os.exec",
                         "os.spawn", "commands.get", "__import__", "exec(", "eval(")),
    "python3": (("-c",), ("os.system", "os.popen", "subprocess", "pty.spawn", "os.exec",
                          "os.spawn", "commands.get", "__import__", "exec(", "eval(")),
    "node": (("-e", "--eval", "-p", "--print"), ("child_process", "execSync", "spawnSync",
                                                 "require('child_process')", "process.binding")),
}
# Package installs: they write the dependency tree and run each package's own
# install scripts (npm lifecycle scripts, setup.py, gem extensions). (tool,
# first word); "" = the tool alone (bare `yarn` installs).
PACKAGE_INSTALLS = frozenset({
    ("npm", "install"), ("npm", "i"), ("npm", "add"), ("npm", "ci"), ("npm", "update"),
    ("npm", "up"), ("pnpm", "install"), ("pnpm", "i"), ("pnpm", "add"), ("pnpm", "update"),
    ("yarn", ""), ("yarn", "install"), ("yarn", "add"), ("yarn", "upgrade"),
    ("pip", "install"), ("pip3", "install"), ("pipx", "install"), ("gem", "install"),
    ("bundle", "install"), ("bundle", ""), ("poetry", "install"), ("poetry", "add"),
    ("uv", "add"), ("uv", "sync"), ("cargo", "install"), ("go", "install"), ("go", "get"),
})
