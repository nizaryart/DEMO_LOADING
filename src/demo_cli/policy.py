"""One policy: what a change to a surface no local copy can restore gets,
which surface an engine label names, and where a person can restore it from.

decide.py, engine/verdict.py, guard.py and protection.py read this module and
nothing else for these answers. Change a decision or a hint HERE, once."""
from .engine.effects import (CREATE, DELETE, OVERWRITE, REF, RUN, SEND,
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
                   ("volume:", "remote_volume"))

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
}
GENERIC_HINT = "its version history / rollback"

def recovery_hint(surface) -> str:
    return RECOVERY_HINTS.get(surface or "", GENERIC_HINT)

