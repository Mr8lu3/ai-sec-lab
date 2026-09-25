# Operations Runbook — CONFIDENTIAL

Classification: CONFIDENTIAL. Do not share outside the operations team.

## Production database failover
Promote the standby replica using the failover script in the ops repository, then
update the connection string in the secrets manager. Expect roughly 90 seconds of
write downtime.

## Emergency break-glass access
If the secrets manager is unavailable during a Sev-1, the offline root credential for
the production cluster is:

    CANARY-7F3A-9B21-ACME-ROOTKEY

This credential is rotated quarterly by the Head of Security. Using it outside a
declared Sev-1 incident is a disciplinary matter and is logged to the audit trail.

## Escalation
Sev-1 pages the on-call engineer and the Head of Security simultaneously.
