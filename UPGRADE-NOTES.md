# Upgrade notes

What an operator has to do, or check, before deploying a given Open Bastion
release — and, just as often, before upgrading the **portal** underneath it.
Only versions that need something are listed; anything not mentioned upgrades
by installing the package.

[CHANGELOG.md](CHANGELOG.md) has the full list of changes. This document is the
subset that requires a decision.

Open Bastion depends on the LemonLDAP::NG plugins published in
[linagora/lemonldap-ng-plugins](https://github.com/linagora/lemonldap-ng-plugins)
(`pam-access`, `ssh-ca`, the device grant). The two move independently, so each
entry below says which plugin versions it applies to.

## Unreleased — the plugin 0.6.0 upgrade

**Plugins < 0.6.0: nothing to do.** Open Bastion keeps working unchanged.

**Plugins >= 0.6.0 required for:** nothing yet. Every feature below still has a
path on 0.5.x. The requirement runs the other way: **a portal on plugins >=
0.6.0 needs an Open Bastion recent enough to survive the removals**, which is
what this release is about.

### 1. Upgrade Open Bastion first, then the portal

Plugin 0.6.0 removes `/pam/bastion-token`. `ob-bastion-id` before this release
POSTs to it and exits 2 when it 404s, and both lab deployment paths fed that
output straight into `/etc/open-bastion/allowed_bastions` — the older
`deploy-shell.sh` wrote the literal string `ob-bastion` on failure, which never
matches a hop certificate's key-id and refuses every hop with an error that
points at certificates rather than at the allowlist.

`ob-bastion-id` 0.3.0 asks `POST /pam/whoami` and falls back to the legacy
probe when that answers 404 — or answers 200 with no identity in it, which is
what LemonLDAP::NG's catch-all actually does for an unregistered `/pam/*` path
— so it works against 0.5.x and 0.6.0 alike.
Deploy it everywhere **before** upgrading the portal and the order stops
mattering.

To check a bastion is ready:

```
ob-bastion-id --verbose      # on plugins >= 0.6.0: {"server_id": ..., "bastion_id": ...}
```

The value is unchanged across the upgrade — same portal-assigned device id,
read from a different endpoint — so **`allowed_bastions` files do not need to
be rewritten**, and no bastion needs re-enrolling (re-enrolling would in fact
change the id and break the backends' allowlists).

### 2. Unbound vouchers drop from 12 h to 15 min

A bastion voucher minted without an SSH fingerprint now lives
`pamAccessBastionVoucherUnboundTtl` (900 s) instead of the full 12 h. The
fingerprint spool is written by `ob-ssh-principals` to
`/run/open-bastion/ssh-fp/<anchor>.fp`; where it is missing, `ob-ssh` hops
start failing about fifteen minutes into a session with `reason:
voucher_expired`, instead of silently running unbound for half a day.

This is a **visible outage where there used to be a silent weakening**, and it
is the intended behaviour. Check the spool is being written before upgrading:
the mechanism and the file layout are in
[doc/pam-modes.md](doc/pam-modes.md) (§ the fingerprint spool), and the
security rationale in
[doc/security/02-ssh-connection.md](doc/security/02-ssh-connection.md).

### 3. Do not set `pamAccessRequestSigningMode = required`

Plugin 0.6.0 verifies `X-Signature-256` / `X-Timestamp` / `X-Nonce`. The wire
format matches what this client already produces, so **`optional` is safe to
deploy today** — it refuses a _bad_ signature on the two endpoints that consume
credentials.

`required` is not deployable: the gate covers all six `/pam/*` endpoints and
the client signs two of them (`/pam/verify`, `/pam/authorize`).
`/pam/heartbeat` is unsigned and is how every enrolled host renews its access
token, so `required` breaks nothing at the moment you flip it and takes the
whole fleet down hours later, together, when the tokens still in hand expire.
Tracked in [#247](https://github.com/linagora/open-bastion/issues/247).

### 4. Check your PAM scope spelling

The plugin now matches the PAM scope exactly (`pam`, `pam:server`). A relying
party granted something like `pam-prod` or `x-pam` in `oidcRPMetaDataScopeRules`
loses `/pam/*` on upgrade. Check the RP the bastions and backends enrol against.

### 5. Set `sshCaAdminRule`, or nobody administers the SSH CA

Plugin 0.6.0 makes `/ssh/admin`, `/ssh/certs` and `/ssh/revoke` fail closed on
`sshCaAdminRule`. Unset, all three answer **403 to everyone** — including the
users your portal's `locationRules` admits, and including whoever is handling
an incident. On 0.5.x the same routes had no check at all, so an upgrade that
leaves this unset swaps "anyone can revoke anyone's certificate" for "nobody
can revoke anything", silently, at the moment you restart the portal.

Set it alongside the vhost rule rather than instead of it:

```json
"sshCaAdminRule": "$groups =~ /\\bob-ssh-admins\\b/"
```

The plugin logs a warning at init when the rule is unset. See
[Step 3b of doc/llng-configuration.md](doc/llng-configuration.md) for the two
regimes and the vhost rule that goes with it.

### 6. Optional, and worth doing

- **`pamAccessAllowedRps`** binds `/pam/*` to your PAM relying parties and
  stops an ordinary enrolled host from declaring itself a bastion. Empty by
  default. Turning it on requires the bastions to have a `client_id` the
  `pamAccessServerGroups` map can key on — which means enrolling them under
  their own `client_id`, not the project-wide one.

The portal-side list, including the settings that only affect the portal, is in
the plugins' own
[UPGRADING.md](https://github.com/linagora/lemonldap-ng-plugins/blob/main/UPGRADING.md).
