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

## 0.7.0

Two independent halves. The host-side one is not optional.

**Host-side — steps 6, 7 and 8. Required whatever your portal runs.** 0.7.0
changes the owner of the fingerprint spool, the `auth` line of
certificate-mode PAM stacks, and the permissions accepted for `cache.key`. None
of it depends on the plugin version.

**Portal-side — steps 1 to 5. Only if you are moving the portal to plugins
0.6.0.** On plugins < 0.6.0 there is nothing to do there — every feature below
still has a path on 0.5.x. The requirement runs the other way: **a portal on
plugins >= 0.6.0 needs an Open Bastion recent enough to survive the removals**,
which is what 0.7.0 provides.

### 1. Upgrade Open Bastion first, then the portal

Plugin 0.6.0 removes `/pam/bastion-token`. `ob-bastion-id` before 0.7.0
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

### 2. Check the fingerprint spool, or hops fail after 15 minutes

Vouchers minted without an SSH fingerprint now expire after 15 minutes
instead of 12 hours: on a host where the spool is not being written,
`ob-ssh` hops start failing about fifteen minutes into a session with
`reason: voucher_expired` — a visible outage where there used to be a
silent weakening.

Check on every bastion and backend before upgrading the portal: log in
with a public key (password logins write no drop), then look **as root**
for a drop written by that login. The spool is mode `0700`, so an
unprivileged `ls` gets `Permission denied`, not an empty listing:

```sh
sudo find /run/open-bastion/ssh-fp -name '*.fp' -newermt '-2 min'
```

Nothing removes a drop when a session ends, so the directory keeps old
ones and a non-empty listing proves nothing — it has to be a _fresh_
drop. No output means the spool is broken: fix it on the host before the
portal moves to plugins 0.6.0 (after the host upgrade, that is step 6:
`ob-fp.socket` enabled and the setup script re-run).

Mechanism: [doc/pam-modes.md](doc/pam-modes.md) § How the fingerprint is
captured; rationale:
[doc/security/02-ssh-connection.md](doc/security/02-ssh-connection.md).

### 3. `pamAccessRequestSigningMode = required` — deployable, in this order

Plugin 0.6.0 verifies `X-Signature-256` / `X-Timestamp` / `X-Nonce` on all six
`/pam/*` endpoints, in `_checkCaller`, before it looks at any caller identity.
Every caller on this side now signs — the PAM module
(`/pam/verify`, `/pam/authorize`, `/pam/heartbeat`), `ob-cert-daemon`
(`/pam/bastion-cert`), `ob-heartbeat`, `ob-bastion-id` (`/pam/whoami`),
`ob-enroll` and `ob-session-monitor` (`/pam/userinfo`). Before
[#247](https://github.com/linagora/open-bastion/issues/247) only the first two
were signed, and `required` would have taken the fleet down.

There is one portal-wide `pamAccessRequestSigningSecret`, and it is the
`request_signing_secret` every host already has in `openbastion.conf`: the
signature proves fleet membership, it does not identify a caller. So the
rollout is about **which hosts hold the secret**, and the order is not
negotiable:

1. Upgrade the hosts to a release carrying #247. A host that has not been
   upgraded still signs nothing on four of the six endpoints.
2. Set `pamAccessRequestSigningMode = optional` on the portal. This already
   refuses a _bad_ signature; it only waives the requirement to sign.
3. Roll `request_signing_secret` out to every host.
4. Confirm every host signs — a host that is silently unsigned is invisible
   until step 5, and then it is not.
5. Only then set `required`.

Doing it in any other order is how this breaks badly rather than visibly.
`/pam/heartbeat` is how every enrolled host renews its access token: switching
to `required` while one host is unsigned breaks nothing at the moment you flip
it, and takes that host down hours later, when the access token it still holds
expires. On a whole fleet, together.

The signature is defence in depth on top of TLS, not a substitute for it. Do
not relax `verify_ssl` because of it.

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

### 6. Re-run the setup script to move the fingerprint spool off `nobody`

Nothing to do portal-side; this is entirely host-side.

`/run/open-bastion/ssh-fp` used to be `0700 nobody`, because the
`AuthorizedPrincipalsCommand` helper wrote the drops itself and `sshd` insists
that helper runs unprivileged. The fingerprint binding therefore depended on a
shared account. A root daemon owns the spool now (#249).

**Installing the package is not enough.** The helper at
`/usr/local/sbin/ob-ssh-principals` is _generated by the setup script_, not
shipped by the package, so an upgraded host still runs the old helper against
the old `nobody`-owned directory. Both keep working — the binding is not lost —
but the old trust root stays in place, and `pam_openbastion` now says so in the
log:

```
SSH fp spool /run/open-bastion/ssh-fp is owned by uid 65534, not root:
the fingerprint binding still rests on that account (#249)
```

To finish the migration, on every bastion and every backend:

```sh
ob-bastion-setup    # or: ob-backend-setup, with the arguments you used before
systemctl status ob-fp.socket
```

The postinst enables `ob-fp.socket` on both roles, so on a packaged upgrade the
daemon is already listening; re-running setup is what replaces the helper and
takes the directory back to `0700 root`. The first deposit through the daemon
also re-asserts ownership, so a host that re-runs setup later converges on its
next SSH login rather than needing a reboot.

If `ob-fp.socket` is not enabled, the helper has nowhere to deposit: logins
still succeed, with **no fingerprint binding** and the missing-drop warning the
module already emits (#192). On a host with `fingerprint_required = true` or a
portal with `pamAccessRequireFingerprint`, that is a visible outage rather than
a silent weakening — check the socket before enabling either.

### 7. Replace `pam_permit` with `pam_deny` in a certificate-mode PAM stack

_Host-side. Applies to any host whose PAM stack was written before
0.7.0, whatever the portal runs._

The `auth` path of the generated certificate/SSH-key stacks was a single
`auth required pam_permit.so`, so `pam_authenticate()` succeeded
unconditionally. The certificate path never calls it, but `sshd` does for
password and keyboard-interactive logins — and `apt install open-bastion`
writes the PAM stack without touching `sshd_config`, so on such a host any
password authenticated any account the `account` phase approved (#180).

The postinst only rewrites `/etc/pam.d/sshd` when the `open-bastion/pam-mode`
debconf answer is not `none`. The recommended install path leaves it at `none`,
so **`apt upgrade` will not fix a stack written by the setup scripts**. Either
re-run `ob-bastion-setup` / `ob-backend-setup` (they back the old files up), or
edit by hand:

```sh
grep '^auth' /etc/pam.d/sshd     # expect: auth required pam_deny.so
```

`/etc/pam.d/sudo` in mode-c is deliberately different and must keep permitting;
leave it alone.

### 8. Check the permissions of `/etc/open-bastion/cache.key`

_Host-side, whatever the portal runs._

A world- or group-readable `cache.key` is now **rejected** rather than used
with a warning. `SECURITY.md` used to suggest creating it with `dd`, which
under root's default umask 022 produces `0644` — so hosts set up from that
recipe are affected. `ob-desktop-setup` has always created it `0600`.

On upgrade the key is ignored and the cache key falls back to machine-id
derivation, which makes every existing offline cache entry undecryptable. That
is a cache miss, not a failure: affected desktop-SSO users need one online
re-authentication. There is no lockout and no cleanup to do.

To restore the strong derivation:

```sh
chown root:root /etc/open-bastion/cache.key && chmod 600 /etc/open-bastion/cache.key
```

The rejection is logged to syslog with that exact command.

### 9. Optional, and worth doing

- **`pamAccessAllowedRps`** binds `/pam/*` to your PAM relying parties and
  stops an ordinary enrolled host from declaring itself a bastion. Empty by
  default. Turning it on requires the bastions to have a `client_id` the
  `pamAccessServerGroups` map can key on — which means enrolling them under
  their own `client_id`, not the project-wide one.

The portal-side list, including the settings that only affect the portal, is in
the plugins' own
[UPGRADING.md](https://github.com/linagora/lemonldap-ng-plugins/blob/main/UPGRADING.md).
