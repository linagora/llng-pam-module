# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- **`ob-bastion-id` now asks `POST /pam/whoami`, not the removed
  `/pam/bastion-token` (#246).** Upstream `lemonldap-ng-plugins` 0.6.0 removes
  `/pam/bastion-token` — it signed a JWT even when the user lookup had failed —
  and replaces its `probe: true` self-identification mode with `POST
  /pam/whoami`, which returns the same portal-assigned device id under the same
  `bastion_id` field. The command falls back to the legacy probe when
  `/pam/whoami` answers 404, or answers 200 with no identity in it — which is
  the usual shape of its absence, see below — so it works against 0.5.x and
  0.6.0 alike and can be deployed before the portal is upgraded. The value is unchanged across the
  upgrade: `allowed_bastions` files need no rewriting and no bastion needs
  re-enrolling.

  The absence of `/pam/whoami` does not usually look like a 404: LemonLDAP::NG
  has a catch-all that serves the portal's own HTML login page, with a 200, for
  any `/pam/*` path no plugin registered. So the fallback triggers on a 200
  carrying no identity as well as on a 404, while a real refusal (403, 5xx) is
  still reported rather than retried against the other URL.

  The request also lost its `curl -f`, which made curl exit non-zero on any 4xx
  _and discard the body_, collapsing every portal-side refusal into the same
  opaque "Request failed" and leaving the HTTP-status branch below it
  unreachable. Telling 404 (endpoint gone) from 403 (caller refused) is what
  the fallback turns on, so the status now survives. New in `--verbose`: the
  whole response document rather than decoded JWT claims. Exit code 2 is now
  "the portal request failed or was refused" and 3 "the portal answered, but
  with no identity in it".

- **The lab deployment scripts no longer invent a `bastion_id` when
  `ob-bastion-id` fails (#246).** `local-test/deploy-shell.sh` wrote the literal
  string `ob-bastion` into `allowed_bastions`, and `deploy-ansible.sh` did the
  same, including on the Mode E path where the capture is skipped by design.
  That literal never matches the `bastion=<id>` field of a hop certificate's
  key-id, so every hop was refused several phases later with errors that point
  at certificates rather than at the allowlist. Both now leave the list empty
  and say so: weaker (an empty list accepts any vouched bastion) but honest,
  and it keeps the rest of the run diagnosable.

### Added

- **The postinst reports a mode-c install on an sshd that still takes passwords
  (#180).** mode-c is the one PAM mode whose generated stack refuses passwords
  outright (`auth required pam_deny.so`), so an sshd left with
  `PasswordAuthentication yes` is a mismatch worth naming. It is only reported,
  never fixed: turning password authentication off from a package script can
  lock out an administrator connected over a password session, and this
  project's convention is that intrusive hardening is opt-in
  (`ob-bastion-setup` writes that drop-in, and it is run deliberately).

  The warning escalates when `UsePAM no` is in effect, because sshd then checks
  `/etc/shadow` itself and never consults the stack — the PAM denial is not
  merely redundant there, it is bypassed.

  Only mode-c. mode-a, mode-b and mode-d all accept a password somewhere by
  design: mode-b and mode-d are given `auth sufficient pam_unix.so`, and mode-a
  carries its token over the password prompt. `sshd -T` is read without `-C`,
  which cannot be built at install time, so a `Match` block re-enabling
  passwords is not seen and the check stays silent — it reports a mismatch it
  can see, and never claims the absence of one.


- **`UPGRADE-NOTES.md`.** What has to be done, or checked, before deploying a
  release — starting with the `lemonldap-ng-plugins` 0.6.0 upgrade: the
  `/pam/whoami` migration above, unbound vouchers dropping from 12 h to 15 min,
  the exact-match PAM scope, setting `sshCaAdminRule` (unset, the three SSH CA
  admin routes answer 403 to everyone from 0.6.0, which turns "anyone can
  revoke anyone's certificate" into "nobody can revoke anything" at the moment
  the portal restarts), and why `pamAccessRequestSigningMode = required` must
  not be turned on yet (#247).
- **`tests/test_ob_bastion_id.sh`.** Replays `ob-bastion-id` against a mock
  portal in every shape it has to survive: `/pam/whoami` answering with an
  identity, the legacy probe answering an id, the legacy probe answering a JWT,
  LemonLDAP::NG's catch-all HTML on one endpoint or both, a 403, a 404 on both,
  and a JWT whose payload is not decodable. The migration itself had no
  coverage at all — the docker integration test only reaches whichever path the
  published demo image happens to take, which today is the legacy fallback,
  and the day that image moves to 0.6.0 the fallback loses its only exercise
  too.

- **`--enable-sudo-fresh-otp` on `ob-bastion-setup` and `ob-backend-setup`
  (#178).** `sudo` keeps its own credential cache (`timestamp_timeout`, 15
  minutes by default, idle-based and rearmed on each use). While it is valid,
  `sudo` skips the PAM `auth` phase entirely, so `pam_openbastion` never runs and
  no LLNG one-time token is asked for — a user who keeps elevating is not
  prompted again, which is not what "a fresh SSO re-authentication for each
  `sudo`" suggests.

  What that does **not** weaken: each token is single-use and consumed by the
  portal, and the `account` phase re-checks authorization live on every `sudo`,
  so an LLNG-side revocation takes effect at once. What it weakens is the
  freshness claim itself.

  The new flag writes `Defaults:%open-bastion-sudo timestamp_timeout=0` into
  `/etc/sudoers.d/open-bastion`, scoped to the SSO group so local break-glass
  admins keep normal `sudo` behaviour. It stays **opt-in**: enabling it by
  default would start prompting on every `sudo` across an upgraded fleet,
  including inside scripts and long maintenance sessions. On a host that already
  has the drop-in, the flag only *adds* the `Defaults:` line — the rest of the
  file is left as the operator wrote it — and the result is `visudo -cf`
  validated before installation, as before. `doc/pam-modes.md` and EBIOS risk
  R-S16 now describe the trade-off and name the flag.

- **The LLNG plugin boundary is now inside the risk study (#218).** The study
  covered the client half only: the four LemonLDAP::NG plugins that carry
  authorization, certificate issuance and machine identity were a trusted
  boundary with no risk sheets, no measures and no conditions of use, while the
  sheets invoked LLNG-side mechanisms (`RequirePKCE`, `RtActivity`, CrowdSec,
  ssh-ca) as givens.

  `doc/security/09-portail-llng.md` adds **eight workshop-4 risk sheets** for the
  server half: caller impersonation on `/pam/*` (no RP/audience binding, and
  `server_group` read from the request body when `pamAccessServerGroups` is
  empty — the configuration the architecture document recommends), unauthorized
  certificate revocation (`/ssh/certs` and `/ssh/revoke` have no authorization at
  all: any SSO account can mass-revoke), KRL corruption taking the whole fleet
  down, CA private-key exposure, enrolment approval by any authenticated user,
  loss of machine identity, **concurrency on the shared session store as a
  systemic pattern** (nine read-modify-write races, not nine bugs), and a cheap
  authenticated denial of service on `ssh-ca`.

  Five conditions of use (CE16–CE19, plus CE20 recording that
  `ssh_key_policy_enabled` defaults to `false`) and thirteen treatment measures
  (MT40–MT52) follow, with the upstream ones marked as such — their owner is the
  plugin maintainer, not this repository. Two of the new risks land in the orange
  zone and are carried to the acceptance table: R-P3 and R-P7 both depend on an
  upstream fix, so accepting them means accepting a delay outside the project's
  control.

  Each sheet also records where its upstream fix stands, because the answer
  moved while the study was being written, and the sheets now carry the full
  inventory rather than a count: all **fifteen** referenced tickets are closed
  and merged upstream (`#50` → PR `#92`; `#53`/`#68` → PR `#88`; `#54`/`#66` →
  PR `#87`; `#55`/`#56` → PR `#86`; `#58` → PR `#76`; `#59` → PR `#77`; `#60` →
  PR `#78`; `#63` → PR `#90`; `#69`/`#72`/`#74` → PR `#80`; `#71` → commit
  `2e5e4c4`, which reached `main` through PR `#90`). **None is released**, so no
  residual score changes — the matrices still describe what an operator can
  deploy today.

  What the acceptance becomes is *not* the same for both orange risks, and the
  dossier no longer says it is. For R-P3 it is a publication delay: the cause is
  fixed upstream and `0.6.0` closes it. For R-P7 it is more than that — the
  merged PRs close the nine identified races but deliver neither real locking nor
  compare-and-swap, so the pattern, and the orange status, survive `0.6.0`. The
  upgrade that brings these fixes is itself disruptive — `/pam/bastion-token`
  disappears (MT51, #248), a voucher bound to no fingerprint drops from 12 h to
  15 min, and the `ssh-ca` admin routes deny until `sshCaAdminRule` is set — so
  it needs planning, which is why the sheets say so rather than leaving it to the
  upgrade night.

  One existing claim is corrected: R-S11 said the CA "can reject" weak keys, with
  the PAM check as defence in depth. In the **released** plugin (`v0.5.2` and
  earlier) the CA enforces no key type or size at all — an RSA-1024 key signs
  without objection — so the PAM policy is not defence in depth there, it is
  **the only control**, and the sheet no longer reads "IMPLÉMENTÉE". Upstream
  `#61` (PR `#78`) adds `sshCaMinKeyBits` and `sshCaAllowedKeyTypes`; from
  `0.6.0`, and only from it, the PAM check goes back to being defence in depth.
  Because that control is the only one until then, and because it ships
  **disabled** (`ssh_key_policy_enabled` defaults to `false`), the condition it
  represents is now recorded as CE20 instead of being asserted in prose — §6 of
  `02-ssh-connection.md` claimed the opposite.

- **The missing EBIOS RM workshops, treatment plan and homologation dossier
  (#212, #216, #217).** `doc/security/` was presented as an EBIOS RM study while
  containing only workshop 4: the word "EBIOS" appeared nowhere inside it, there
  were no essential assets, no risk sources, no strategic scenarios, and no
  explicit likelihood or severity scales — the matrices assumed scales that were
  never written down. There was also no treatment plan (25 free-text "pistes"
  with no owner, priority, due date or status) and no decision artefact at all:
  no perimeter of homologation, no conditions of use, no residual-risk
  acceptance.

  Five documents are added:

  - `04-atelier1-cadrage-socle.md` — perimeter, business values, supporting
    assets, the **severity and likelihood scales** the matrices were using
    implicitly, the risk-zone definition, seven feared events, and the security
    baseline with its gaps. Every one of the 39 risk sheets is attached to
    exactly one feared event.
  - `05-atelier2-sources-de-risque.md` — seven risk sources, six target
    objectives, the SR/OV relevance grid, and why the discarded pairs were
    discarded — including the LLNG portal administrator, who is not a risk the
    product can reduce and is stated as a trust assumption instead.
  - `06-atelier3-scenarios-strategiques.md` — ecosystem mapping with threat
    levels, and seven strategic scenarios, each saying what the architecture
    opposes **and what it does not**.
  - `07-plan-de-traitement.md` — the treatment plan: 29 measures with the risk
    they reduce, nature, priority, owner, due date and state, plus four measures
    explicitly discarded with their reason. Delivered measures stay in the plan
    with their PR reference — that is what was missing when two shipped measures
    were still listed as future work.
  - `08-dossier-homologation.md` — the decision artefacts: dossier front matter,
    the homologation perimeter (**the LLNG portal and its four plugins are
    inside it**), what is explicitly out with what is expected of the operator,
    four trust assumptions, **fifteen conditions of use** with how to verify each
    on target, and the residual-risk acceptance table.

  Plus `doc/security/README.md`, which maps each document to its workshop.

  Owner names, dates, product version and acceptance decisions are left as
  `À COMPLÉTER`: they belong to the homologation authority, not to the analysis.
  The dossier says so rather than inventing them.

  The risk-zone definition is also unified: `01-enrollment.md` used thresholds on
  (P, I) and `99-risk-reduce.md` used a score, with listings that did not match
  either. There is now one definition (score = likelihood × severity) in
  workshop 1, and the checker fails if a zone listing does not follow from it.

### Fixed

- **Three defects in `ob-bastion-id`'s own error paths.**

  `die()` logged `$*`, which joins the message with the exit code passed as its
  second argument, so every call that set one ended its message with a stray
  digit — `…/pam/bastion-token probe: <!DOCTYPE html>… 2`. Pre-existing, but
  this release adds call sites that pass a code and redefines what 2 and 3
  mean.

  A portal answering 200 on both endpoints without an identity exited **2**
  ("the request failed or was refused") where the contract says **3** ("the
  portal answered, but with no identity in it"). Nothing failed or was refused
  there — both endpoints answered 200. Its three sibling errors already used 3.

  A JWT whose payload is not base64url killed the script at the assignment,
  under `set -e` with `pipefail`, before its own `die` could run: the caller got
  rc=1 and no message, and the man page described a diagnostic that could not
  happen.

### Security

- **The portal `locationRules` that guard `/device` and the SSH CA admin routes
  are now shipped and documented (#195).** Where the authorization for these
  routes lives depends on the plugin version, and the two regimes fail in
  opposite directions, so the guide states both:

  - **Plugins ≤ `v0.5.2`** (every released version): the ssh-ca plugin performs
    no authorization on `/ssh/admin`, `/ssh/certs` and `/ssh/revoke`. The vhost
    rule is the only control, and without it any SSO account can list every
    issued certificate and revoke anyone's — an org-wide SSH outage.
  - **Plugins ≥ `0.6.0`**: `sshCaAdminRule` is the plugin's own control and it
    is fail-closed. Unset, the three routes answer 403 to everyone, including
    the users `locationRules` would let through — so a portal configured with
    the vhost rule alone loses its admin UI on upgrade, incident handling
    included. Both `docker-demo-cert` and `docker-demo-maxsec` now set
    `sshCaAdminRule` alongside the vhost rules, so the demos keep working across
    the version boundary.

  `/device` is documented as the two layers it actually has:
  `oidcRPMetaDataOptionsAllowDeviceAuthorization` is a `boolOrExpr` evaluated on
  the approval **decision** per relying party — `= 1` is an activation flag, not
  a permission, but any other value is compiled and evaluated against the
  session — while `locationRules` on `^/device` gates the **page** for every RP
  at once. The guide previously mentioned only the vhost layer, which is the
  weaker of the two.

  The two traps the guide calls out are real, but the mechanism given for each
  was wrong and is corrected here. `^/device$` does **not** fail to fire: the
  approval form posts to `PORTAL_URL/device` with `user_code` and `action` in
  the body, so `REQUEST_URI` is `/device` and an anchored rule matches the
  decision. What it misses is the page (`/device?user_code=...`) and a crafted
  `POST /device?user_code=…&action=approve`. And restricting `/ssh/revoked` does
  **not** break fleet-wide revocation propagation: backends fetch the KRL with
  an anonymous `curl`, and a request with no session never reaches `grant()` —
  it is served by the plugin's unauthenticated route. The real cost is a 403 on
  a KRL fetch made with a session, by an administrator in a browser. The
  `(\?|/|$)` guard is right either way.

  `tests/test_ob_llng_location_rules.sh` pins all of it. The `/device` check now
  compiles the rule and runs the page, decision and query-string-POST URIs
  through it, replacing a textual heuristic that both skipped an anchored form
  hidden inside an alternation and rejected a safe `^/device(\?.*)?$`. The
  route-separation check gained `/ssh/adminfoo`, `/ssh/certsx` and
  `/ssh/revoketoo`, so weakening one alternative cannot pass on the strength of
  the others. A new check requires `sshCaAdminRule` wherever `sshCaActivation`
  is on. And the drift check covers all four copies of the normative content —
  the guide, both EBIOS documents and this file — instead of the guide alone.

  The group names in the examples (`ob-approvers`, `ob-ssh-admins`) exist
  nowhere in the shipped configuration: the guide now says to substitute your
  own and to check they appear in the session, because a rule naming a group
  nobody holds returns 403 for everyone and looks exactly like a rule that
  works. The `lmConf-<n>.json` snippet is shown as a complete object to be
  merged into the existing `locationRules`, since a second top-level
  `locationRules` silently replaces the first. And the Manager table warns to
  copy from the rendered page: pasted from the raw Markdown, the escaped `\|`
  becomes a literal pipe in the compiled regexp, the key matches nothing,
  `grant()` falls through to `default: accept`, and the admin routes stay open
  with no error anywhere.

- **Certificate-mode sshd PAM stacks now refuse password authentication
  (#180).** The `auth` path of the stacks written for the certificate/SSH-key
  modes consisted of a single `auth required pam_permit.so`, so
  `pam_authenticate()` returned success unconditionally. The certificate path
  never calls `pam_authenticate()` (sshd only runs `pam_acct_mgmt()` for a
  pubkey/certificate login), but sshd _does_ call it for password and
  keyboard-interactive authentication: on a host where those are still enabled
  — which is what `apt install open-bastion` leaves behind, since the postinst
  writes the PAM stack but never touches `sshd_config` — any password
  authenticated any account the `account` phase approved.

  Every generated `/etc/pam.d/sshd` for those modes (Debian postinst `mode-c`,
  `ob-bastion-setup`, `ob-backend-setup`, the `docker-demo-cert` and
  `docker-demo-maxsec` images) and every stack documented for copy-paste now
  has a single `auth required pam_deny.so`: an explicit, unconditional refusal
  that returns `PAM_AUTH_ERR`. Certificate logins are unaffected. Setting
  `PasswordAuthentication no` / `KbdInteractiveAuthentication no` in
  `sshd_config` — written by both setup scripts, but _not_ by the package
  postinst — is still recommended so sshd never prompts at all.

  The `mode-c` `/etc/pam.d/sudo` stack keeps permitting, because `mode-c` is
  the "SSH keys, sudo without a password" scenario. It now uses the canonical
  fail-closed permit — `auth [success=1 default=ignore] pam_permit.so`, then
  `auth required pam_deny.so`, then `auth required pam_permit.so` — which
  succeeds on the intended path but refuses if `pam_permit` is missing or
  errors. The trailing `pam_permit` is required: without it the jump lands past
  the end of the stack with no positive result recorded and PAM returns
  `PAM_PERM_DENIED`, which would have broken sudo outright.

  `tests/test_ob_pam_runtime.sh` (new) now calls `pam_authenticate()` on each
  generated stack and asserts the verdict, instead of only checking the text.

  **Upgrading:** the postinst only rewrites `/etc/pam.d/sshd` and
  `/etc/pam.d/sudo` when the `open-bastion/pam-mode` debconf answer is not
  `none`. The recommended install path (`apt install` then `ob-bastion-setup` /
  `ob-backend-setup`) leaves it at `none`, so `apt upgrade` will _not_ replace
  the stack those scripts wrote. On such a host, re-run `ob-bastion-setup` or
  `ob-backend-setup` (they back the old files up first), or edit
  `/etc/pam.d/sshd` by hand and replace `auth required pam_permit.so` with
  `auth required pam_deny.so`. Check with
  `grep '^auth' /etc/pam.d/sshd`.

- **The fingerprint spool is harder to forge, and what it is worth is now
  written down (#235 review).** The spool's trust root is the `nobody` account:
  `sshd` requires a non-privileged `AuthorizedPrincipalsCommandUser`, so the
  helper that writes the drops runs as `nobody` and the directory must be
  writable by it. Code execution as `nobody` can therefore read the deposited
  fingerprints and write false ones, and none of the module's existing checks
  (`O_NOFOLLOW`, `nlink == 1`, mode `0600`, drop owner == directory owner) is
  designed against an attacker who is already inside that perimeter. Three
  changes narrow it without changing its nature:

  - The anchor `/proc/<pid>` must be a live process owned by **root**. The
    anchor is chosen by process *name*, and `prctl(PR_SET_NAME)` accepts fifteen
    characters while `sshd-session` is twelve — so a local user could put a
    process by that name in the ancestry of their own `sudo` and choose which
    drop was read. That half of the forge needed no privilege at all.
  - A drop older than its anchor process is refused. Nothing removes a drop when
    a session ends and the principals helper does not run for password logins,
    so once a PID was recycled the new session inherited the previous
    occupant's binding, with every ownership and mode check passing. On Linux
    the mtime of `/proc/<pid>` is the process start time, which makes the
    comparison exact.
  - A service-account authentication resting on a spool-derived fingerprint,
    rather than on `sshd`'s own `SSH_USER_AUTH`, is logged at WARN and the
    provenance is carried in the reason of the single audit success event. It is
    a root grant whose integrity rests on `nobody`, and the trail should be able
    to say so afterwards.

  The real fix — a socket-activated root daemon identifying its caller with
  `SO_PEERCRED`, the pattern `ob-cert-daemon` already uses — is tracked in
  [#249](https://github.com/linagora/open-bastion/issues/249).
  `doc/security/99-risk-reduce.md` states the residual plainly, next to the
  R-S3 / R-S15 reduction it underwrites.

- **`fingerprint_required` is documented where an operator looks for it.** It is
  condition of use **CE09** of the homologation dossier and the assumption
  behind the R-S3 / R-S15 residual scores, but `doc/admin-guide.md`'s "SSH Key
  Policy" section did not mention it, and the accepted alias
  `ssh_fingerprint_required` appeared in no document at all.

- **`fingerprint_required` now covers service accounts too, and their SSH check
  actually runs.** The service-account branch of `pam_sm_acct_mgmt` returned
  `PAM_SUCCESS` before the enforcement block, so the setting documented as
  covering "every SSH login" skipped them. Worse, their account-phase check read
  `SSH_USER_AUTH` alone — which a modern OpenSSH does not set for a plain public
  key — and for a public-key login that is the *only* check that runs, since
  `sshd` never calls `pam_authenticate()` on that path. It resolves through the
  spool now, like the `sudo` path, and `fingerprint_required` is enforced before
  the early return.

- **A missing `.key` drop is no longer reported as a missing key binding.**
  `read_spool_drop()` is shared between the `.fp` and `.key` suffixes and warned
  identically for both. The `.key` drop only exists when `sshd` passes `%t` to
  the helper; a host configured from the shorter `%u %f` form still shown in
  places has none, and its absence is a missing capability the caller handles by
  falling back, not a missing security binding. WARN for `.fp`, DEBUG for the
  rest.

- **Service-account `sudo` with `sudo_nopasswd = false` now works at all
  (#194).** The fingerprint check read `SSH_USER_AUTH` only. That variable does
  not exist in a `sudo` PAM handle, so the check could never succeed and the
  branch always returned `PAM_AUTH_ERR` — leaving `sudo_nopasswd = true`, which
  grants sudo with no proof of identity, as the only workable setting, and
  pushing admins toward it. The fingerprint is now also recovered from the
  principals spool (`/run/open-bastion/ssh-fp`), which the SSH session populated
  and which `sudo` inherits through the process tree, so both settings do what
  they say. On a host without the principals helper there is still no
  fingerprint in either context and `sudo_nopasswd = false` refuses, which is
  the fail-closed answer.

### Security

- **A missing SSH fingerprint drop is now visible, and can be made fatal
  (#192).** When the principals spool exists but this session's drop is absent —
  post-upgrade drift, a lost `tmpfiles.d` entry, or a password login on a
  cert-aware host — the module dropped the fingerprint binding with a DEBUG line
  and authorized the session anyway. `doc/security/99-risk-reduce.md` credits
  that binding with reducing R-S3 and R-S15, and the bastion voucher TTL is only
  capped by the SSO certificate expiry when a fingerprint was supplied, so a
  provisioning failure silently removed a control the risk matrix depends on.

  The missing drop is now logged at **WARN** (the spool directory being absent
  altogether stays at DEBUG: that host simply does not use the helper), and a new
  opt-in `fingerprint_required = true` refuses an SSH login whose fingerprint
  cannot be recovered instead of authorizing without the binding. Enable it on
  certificate-mode hosts — the EBIOS study now names it as a condition of use for
  the R-S3 / R-S15 residual scores. Do **not** enable it in the token-only modes,
  where no fingerprint ever exists and every SSH login would be denied.

  The portal is growing the server-side half of the same control:
  `linagora/lemonldap-ng-plugins#86` caps a voucher that no fingerprint binds at
  `pamAccessBastionVoucherUnboundTtl` (900 s instead of 12 h) and adds
  `pamAccessRequireFingerprint` to refuse the unbound case outright. Once that
  ships, a missing spool drop stops degrading silently and starts breaking
  visibly: `ob-ssh` hops fail about fifteen minutes into the session with
  `voucher_expired`. That is the better failure, but it is a failure — which is
  the argument for turning `fingerprint_required` on **before** the portal is
  upgraded, so the refusal lands at login with an audited reason instead of on a
  hop a quarter of an hour later.

### Changed

- **A failing `ctest` now keeps its log, and the concurrency test says why it
  failed (#244).** `test_offline_cache` failed once in the Rocky 9 RPM job and
  passed on a re-run of the same commit — but the re-run replaced the workflow
  log, which was the only record of which sub-test failed and on which
  assertion, so the flake could not be diagnosed at all. The three jobs that run
  `ctest` now upload `Testing/Temporary/` as an artifact when the test step
  fails, so the evidence survives a re-run.

  Two of the three jobs could not have held that evidence: `test_offline_cache`
  is only compiled with `INSTALL_DESKTOP=ON` (`tests/CMakeLists.txt:123`), which
  neither the build matrix nor the sanitizer job passed. Both now do, so the
  test of #244 also runs under ASan/UBSan — where a concurrency bug is most
  likely to be caught — and on two more distributions. The artifact names carry
  `github.run_attempt`, because artifacts are immutable per run and a partial
  re-run keeps attempt 1's: a fixed name would make the re-run's upload fail
  with `409 Conflict` and lose exactly the confirmation evidence #244 is about.
  `fail-fast: false` on both matrices, because a cancelled step never runs
  `if: failure()`, so one leg's failure would silently drop its sibling's log.

  `test_concurrent_failed_attempts` (the `#186` lockout regression) also had
  four failure paths that printed nothing. Three returned "FAILED" with no
  reason: a failed `pipe()`, a failed `fork()`, and a failed
  `offline_cache_get_entry()`. The fourth was worse — a short write to the
  release barrier broke out of the loop, and `close(barrier[1])` then released
  the remaining children through EOF, so every increment still landed and the
  test **passed silently** on a barrier that had not worked. Each path now names
  what went wrong, and the barrier one fails: that is a verdict change, not just
  added output.

  Each child also reports its `verify()` result through its exit status, decoded
  by name in the parent (`a child's verify returned Entry not found`), with 127
  reserved for a wrong password that verified. This does **not** cover the
  lost-increment mode of #186 — there the write is lost while `verify()` still
  returns `ERR_PASSWORD`, so every child exits 0 and that mode still surfaces as
  the bare `failed_attempts=5 expected=6` caught by the counter assertion. What
  the channel adds is a name for the other failures: a child that errored out
  early, or one that was killed. The counter is now compared against the number
  of children actually started, so a fork failure no longer prints a second,
  false layer of failure on top of the one already reported.

- **`ob-builder` artefacts that carry the client secret are no longer
  world-readable, and no longer commit themselves (#203).** With
  `client_secret_mode: embedded` the OIDC client secret is written in clear text
  into the shell installer (`0755`) and the Ansible role's `defaults/main.yml`
  (`0644`). Both are now restricted to the building user (`0700` / `0600`), and
  an embedded bundle gets a `.gitignore` at its root so a `git add -A` in a
  surrounding working tree cannot publish it. Bundles built with the default
  `client_secret_mode: prompt` are unchanged — nothing secret reaches the disk,
  so there is nothing to hide. The repository's own `.gitignore` also covers the
  bundle directories that were sitting untracked in the working tree.

- **`ob-ssh` / `ob-scp` / `ob-sftp` no longer have a privileged shortcut around
  `ob-cert-daemon` (#202).** `request_bastion_cert()` took a
  `[ -r "$SERVER_TOKEN_FILE" ]` branch that called `/pam/bastion-cert` directly
  with the bastion's bearer token whenever the caller could read the token file
  — root, or a lab that had relaxed the `0600`. It was an escape hatch around
  the SO_PEERCRED design, with none of the daemon's checks. It is gone: root and
  unprivileged callers now take the same audited path through
  `ob-cert-request` → `ob-cert-daemon`. `get_server_token()` and
  `build_curl_opts()` went with it — the shared library no longer contacts the
  portal at all. `SERVER_TOKEN_FILE` stays in `ssh-proxy.conf`: it is read by
  `ob-cert-daemon`, which parses the same file.

- **The bastion→backend host-key policy can now be tightened (#202).** The three
  connectors passed `-o StrictHostKeyChecking=accept-new` *before* the
  operator's `SSH_OPTIONS`, and `ssh` keeps the **first** value it is given for
  an option — so the trust-on-first-use default could not be overridden at all.
  The default is now emitted only when `SSH_OPTIONS` does not set the option, so
  a site that pre-seeds `/etc/ssh/ssh_known_hosts` can refuse unknown backend
  host keys:

  ```
  SSH_OPTIONS="-o StrictHostKeyChecking=yes -o GlobalKnownHostsFile=/etc/ssh/ssh_known_hosts"
  ```

  The TOFU trade-off itself — an attacker on the bastion→backend path can MITM
  the *first* connection to a backend and read the session, though nothing
  reusable is captured — is now documented in `doc/admin-guide.md`,
  `man ob-ssh` and risk R-S9 of the EBIOS study, where it had never been stated.

- **Every EBIOS risk matrix now agrees with the risk sheets it summarises
  (#213, #214, #215).** The five matrices in `doc/security/` were maintained by
  hand and had drifted from the sheets: risks placed one column off, residual
  scores no sheet states, the consolidated table missing 11 of the analysed risks
  and carrying two identifiers (`R-S24`, `R-S25`) that had no sheet at all, and
  `99-risk-reduce.md` stating three different values for `R-S18` on three lines.
  An evaluator reads the matrix, not the sheets.

  All five are now derived from the sheets, cell by cell, with no local
  re-evaluation; the conditional "clients OIDC distincts" configuration, which
  the enrolment matrix used to apply silently, has its own labelled matrix.
  `R-S24` and `R-S25` gained full risk sheets in
  `doc/security/02-ssh-connection.md` (vectors, mitigating factors, remediation,
  residual score) rather than being dropped, and the service-account risks now
  appear in the SSH matrices so those cover the whole study.

  `tests/ebios_matrix_check.py`, run by `tests/test_ob_ebios_matrices.sh` in CI,
  re-derives every matrix from the 39 sheets and fails on any divergence, any
  missing analysed risk, and any identifier without a sheet — including the score
  repeated in each `99-risk-reduce.md` section heading.

  The backlog was swept against the shipped code at the same time: the
  "privileged session collector" listed under R-S19 as *not retained* was
  delivered by #157 (`ob-record-sink` is socket-activated, so the "new permanent
  service" objection is void, and it writes root-owned files), and "session
  recording" listed under R-S6 as an improvement is on by default and
  fail-closed. Both are marked delivered, with what genuinely remains.

- **An unrecognised key in `openbastion.conf` is now logged instead of silently
  ignored (#229).** The parser dropped unknown keys without a word, which made
  every documentation typo invisible: `doc/security/02-ssh-connection.md` told
  operators to set `auth_cache_offline_ttl` (and `auth_cache_ttl`), neither of
  which the module has ever parsed, so an operator sizing the offline
  authorization window for a planned LLNG outage got no error and no effect.
  Unknown keys are still ignored — no host can be locked out by this — but each
  one now produces `open-bastion: unknown configuration key '<key>' in <file>,
  ignored` in syslog. The key alone is logged, never the value; the file is the
  one actually parsed, since the PAM `conf=` argument can point elsewhere. PAM
  module arguments are unaffected.

  The report is only useful while it means something, so every key the project
  itself writes into `openbastion.conf` is recognised and stays silent: the
  three `ob-heartbeat(8)` ones (`node_role`, `report_sessions`,
  `max_reported_sessions`), and the five that `ob-bastion-setup`,
  `ob-backend-setup` and the `ob-builder` templates emit but nothing reads back
  (`cache_enabled`, `cache_dir`, `cache_ttl`, `create_home`, `default_shell`).
  Without them `config_load()` — which runs once per PAM process — would have
  put three to five warnings in syslog on every login of every deployed host,
  burying the one typo this exists to surface.
  `tests/test_ob_config_keys.sh` now reads the generators and the shipped
  example and fails if either emits a key the parser does not know.

  The documentation is corrected with it: the PAM authorization cache has **no**
  local TTL setting — the portal supplies it in the `/pam/authorize` response
  from LLNG's `pamAccessOfflineTtl`, and the module falls back to 24 h when the
  portal sends none. `openbastion.conf`'s `offline_cache_ttl` governs the
  desktop-SSO credential cache only. `cache_ttl` appears in `openbastion.conf`
  because the setup scripts write it there, but it is read only from
  `nss_openbastion.conf`, by the NSS module.

- **`doc/offline-mode.md` now states what actually works during a portal outage
  (#165).** A ten-row matrix derived from the code and the generated `sshd`
  configurations: what keeps working (user resolution, certificate logins,
  service-account `sudo`), what does not (`ob-ssh`/`ob-scp`/`ob-sftp`, enrolment,
  revocation), and the two cache TTLs that must be sized together.

  `sudo` for an SSO user is the row that needed splitting rather than a ❌. The
  cache is an _authorization_ cache, not an authentication one, so the `auth`
  phase cannot be served offline — but `sudo` only runs that phase when its own
  credential has lapsed (`timestamp_timeout`, 15 min, idle-based). While it is
  valid `sudo` never calls `pam_authenticate()`, and the `account` phase answers
  `sudo_allowed` from the authorization cache. A user who elevated recently
  therefore keeps elevating during an outage. Conversely, `--enable-sudo-fresh-otp`
  (#178) sets `timestamp_timeout=0` and so removes the window entirely: on such a
  host no SSO user can `sudo` at all while the portal is down. The same
  correction is applied to `doc/security/02-ssh-connection.md`, whose "les
  escalades sudo sont refusées" was an assumption R-S17 rests on.

  It also answers a question that comes up on every deployment: can a user keep a
  **personal SSH key on the bastion** as an outage fallback? In Mode E, no — the
  backends set `AuthorizedKeysFile none` and `sshd` refuses a plain key before
  PAM is consulted. In the key modes, yes, under four stated conditions — and the
  documentation says what it costs: a long-lived private key on the bastion, not
  bounded by a certificate TTL and not revocable through the portal, and a hop
  that is no longer vouched. One assumption is corrected: the audit trail
  **survives**, because a plain `ssh` run from inside a recorded bastion session
  is captured by the pty recorder; what is not recorded is a `ssh -J bastion`
  ProxyJump from a workstation.

  The EBIOS risk R-S17 (total lockout) gains the same note in French, and
  `doc/pam-modes.md` points Mode C at the matrix. The key-mode path is labelled
  as analysis, not as a tested procedure: the end-to-end lab validation the issue
  asks for has not been done.

- **A world- or group-readable `/etc/open-bastion/cache.key` is now rejected
  instead of used with a warning** (offline auth cache, desktop SSO). Versions
  up to 0.6.2 accepted such a key and merely logged a warning. `SECURITY.md`
  used to document creating the key with
  `dd if=/dev/urandom of=/etc/open-bastion/cache.key bs=32 count=1`, which under
  root's default umask 022 produces a `0644` file — so hosts set up from that
  recipe are affected. **Effect on upgrade:** the key is ignored, the cache key
  falls back to machine-id derivation, and every _existing_ offline cache entry
  becomes undecryptable — a cache miss, not a failure: affected desktop SSO
  users need one online re-authentication and the cache repopulates. There is no
  lockout and no manual cache cleanup to do. **Remedy (restores the strong
  derivation):** `chown root:root /etc/open-bastion/cache.key && chmod 600
/etc/open-bastion/cache.key`. The rejection is logged to syslog with that
  exact command. `ob-desktop-setup` has always created the key `0600`, so hosts
  set up with it are unaffected.

### Security

- **A mistyped boolean in `openbastion.conf` no longer silently means `false`
  (#183).** The parser mapped every unrecognised value to `false`, so
  `verify_ssl = TRUE` or `verify_ssl = tru` turned TLS certificate verification
  OFF without a word — fail-open on the setting that protects every call to the
  portal, and the same for ~25 other security booleans. Boolean settings now
  accept only `true`/`yes`/`1`/`on` and `false`/`no`/`0`/`off`; anything else
  keeps the safe default, logs the offending key and value to syslog, and makes
  `config_validate()` refuse the configuration (new return code `-6`), which
  aborts the PAM module instead of running with a guessed value. Inline
  comments (`verify_ssl = true # prod`) are stripped before that strict parse,
  so an existing config file cannot become fatal on upgrade; a `#` inside a
  token and the values of secret-bearing keys are never touched (see
  `doc/configuration.md`). `ob-cert-daemon` was already safe on this key for a
  different reason: it treats anything that is not an explicit `false`/`no` as
  `true`, so a typo leaves verification ON rather than turning it off.
- **The NSS module no longer disables TLS verification on a typo (#183).**
  `nss_openbastion.conf` had its own parser with the same fail-open expression
  (`strcmp(value, "true") == 0 || strcmp(value, "1") == 0`), so `verify_ssl =
TRUE` or `= yes` silently turned certificate verification OFF for every NSS
  call to the portal. It now reuses `str_parse_bool_strict()`. Unlike the PAM
  module it does not refuse to start — it is loaded into every process that
  resolves a name, and failing there would make all SSO users unresolvable and
  lock the host out — so it fails closed on the security property instead: an
  unrecognised value is reported to syslog and the safe value (verification ON)
  is used.
- **The request-signing nonce is now covered by the HMAC (#188).** With
  `request_signing_secret` configured, the client sent `X-Nonce` alongside
  `X-Signature-256`, but the signed message was only
  `timestamp.method.path.body` — the nonce was not in it (despite a comment
  claiming otherwise). A captured request could therefore be replayed with a
  fresh nonce and still verify, defeating the replay window the nonce exists
  for. The signed message is now `timestamp.nonce.method.path.body` and the
  format is documented in `SECURITY.md`.
- **`ob-builder` validates `apt_url`, `apt_suite` and `apt_component` (#190).**
  The three values are concatenated into the `deb [signed-by=…] URL SUITE
COMPONENT` line and interpolated verbatim into the generated installer, which
  runs as root on every target. They were the only build inputs with no
  validation, so `apt_url: "https://x/$(…)"` executed at install time and an
  embedded newline injected arbitrary `sources.list` entries. They are now
  checked against shell-safe charsets, and a regression test feeds hostile
  values through both the CLI and the YAML config path.

### Removed

- **`secret_store`, the last dead cryptographic module (#225).** Same shape as
  the token cache above: `src/secret_store.c` was compiled into the PAM module
  and every entry point — `secret_store_init`, `_get`, `_put`, `_delete`,
  `_rotate_key` — was reachable only from its own unit test. Nothing in the
  authentication path ever stored or read a secret through it. Removed with its
  header, its test, and the `secrets_encrypted` setting (plus the
  `no_encrypt_secrets` module argument) that was parsed, defaulted and validated
  without ever reaching a store.

  This removes AES-GCM code and file writes under `/etc/open-bastion` from a
  root PAM module that had no use for them, and it settles two findings that
  landed inside the dead module: #187 (missing size check in `secret_store_get`,
  fixed in #222 and now moot) and #184 (machine-id-only key derivation, no
  key-file support — the honest fix being to stop claiming the capability).

  `SECURITY.md` and `doc/security/00-architecture.md` advertised
  `secrets_encrypted = true`, "encrypt secrets at rest". They now state the
  truth: secrets in `openbastion.conf` are protected by file permissions only
  (root-owned `0600`, enforced by the module, which refuses to read the file
  otherwise), and the way to avoid a secret on disk is not to write one
  (`client_secret_mode: prompt`, or `ansible-vault`).

  **Not** removed: `src/cache_key.c` and `src/offline_cache.c`, which do the
  machine-id/key-file derivation for the offline credential cache and are
  genuinely used.

- **Dead token cache, `client_context`, and kernel-keyring settings.** Three
  things `SECURITY.md` documented as active features were never wired into the
  PAM chain, so this is a documentation-accuracy fix as much as a cleanup:
  - The **encrypted token cache** (`src/token_cache.c`) was initialised,
    destroyed and invalidated, but `cache_lookup()`/`cache_store()` had no
    caller anywhere outside its own unit test — nothing ever put a token in it
    or read one back. Removed along with its orphaned settings
    (`cache_enabled`, `cache_dir`, `cache_ttl`, `cache_ttl_high_risk`,
    `high_risk_services`, `cache_encrypted`, `cache_invalidate_on_logout`), the
    `no_cache` / `no_cache_encrypt` module arguments, and the `ENABLE_CACHE`
    build option. Rewiring it would have reopened an offline authentication
    path nothing currently needs, so it was deleted rather than reconnected.
  - **`client_context`** (`src/client_context.c`) was compiled into the module
    with zero callers. Removed. Its risk-based-TTL logic only ever fed the
    token cache.
  - **`secrets_use_keyring` / `secrets_keyring_name`** defaulted to enabled and
    were documented as "use kernel keyring", but no `add_key`, `request_key` or
    `keyctl` call existed anywhere — `secret_store` only stored and freed the
    two fields. Removed, together with the `no_keyring` module argument.

  Unknown configuration keys have always been ignored silently, so an existing
  `openbastion.conf` still loads; the removed keys simply no longer do anything
  (they did not before either).

  **Not** removed: `src/auth_cache.c`, a different component that is genuinely
  used and already fails closed when key derivation fails. The
  `cache_rate_limit_*` settings also stay — they protect the authorization
  cache, not the deleted one.

### Changed

- **`SECURITY.md` now documents the cache that actually exists.** The "Token
  Cache Security" section described the deleted cache, and its stated file
  layout (`[IV][Tag][Ciphertext]`) did not match the code either. It is
  replaced by an "Authorization Cache Security" section covering the real
  `LLNGCACHE04` cache: its true layout (HMAC-authenticated plaintext expiry
  header, magic, IV, ciphertext, then GCM tag), fail-closed key derivation,
  `(user, server_group, host)` isolation, server-provided TTL, and the
  brute-force protection on cache lookups. The French mirror
  (`doc/security/00-architecture.md`) was corrected the same way.

### Fixed

- **The SSH key policy is now actually enforced, fail-closed (#181).**
  `ssh_key_policy_enabled` was documented as implemented but enforced nothing.
  The check called `extract_ssh_algorithm()`, which reads only `SSH_USER_AUTH`
  — a variable sshd does not export to the PAM environment during
  `pam_acct_mgmt` on OpenSSH >= 9.8 — and when it returned `NULL` the whole
  policy block was silently skipped. `ssh_key_policy_check_rsa_size()` had no
  production caller at all, so `ssh_key_min_rsa_bits` was inert.
  - `ob-ssh-principals` (installed by `ob-bastion-setup` / `ob-backend-setup`)
    is now called with sshd's `%t` and `%k` tokens and writes a second spool
    drop, `/run/open-bastion/ssh-fp/<anchor>.key`, carrying `v=1` / `fp=` /
    `alg=` / `key=`. The existing `<anchor>.fp` drop is untouched, so an older
    module reading it keeps working against a newer helper.
  - `pam_openbastion` decodes the key blob itself (type name, and the RSA
    modulus size — the only place that size exists), cross-checks it against
    the fingerprint drop, then runs the full policy check including
    `ssh_key_min_rsa_bits`.
  - When the policy is enabled and the key cannot be identified, the account
    phase now **denies** instead of skipping, with an explicit log line naming
    the fix (re-run the setup script).
  - `ssh_key_policy_enabled` still defaults to `false`; with the policy off
    nothing in this path runs and behaviour is unchanged. Because a package
    upgrade replaces the PAM module but not the helper in `/usr/local/sbin`,
    the postinst warns when it finds the policy enabled next to a pre-v1
    helper, and the docs tell you to re-run `ob-bastion-setup` /
    `ob-backend-setup` before enabling it.

- **A server-supplied `gid` is no longer validated against the synthetic UID
  range.** The NSS module briefly checked the portal's `gid` (an LDAP
  `gidNumber` exported via `pamAccessExportedVars`) against
  `[min_uid, max_uid]` — default `[10000, 60000]` — so an ordinary group such as
  `1000` fell outside it and was silently replaced by `default_gid`. GIDs now
  have their own policy range, `min_gid`/`max_gid` in
  `nss_openbastion.conf`, defaulting to `[1000, 65533]`: the Debian/RHEL
  boundary between system groups (`SYS_GID_MAX=999`) and user groups
  (`GID_MIN=1000`). `gid 0` and `nogroup` are refused whatever the
  configuration says. An out-of-policy gid is replaced by `default_gid` and
  logged to syslog with the offending value — never silently.

- **A rejected `/pam/verify` token now fails cleanly instead of looking like a
  server outage.** On any negative verdict — expired or invalid one-time token,
  wrong token type, or an SSH fingerprint the portal refuses — the pam-access
  plugin answers `{"valid":false,"error":"<reason>"}` with no `user` field
  (`user` is only present on a positive verdict). The client required `user`
  unconditionally and bailed out with `Missing required 'user' field in
response`, returning `PAM_AUTHINFO_UNAVAIL` — which reads as a server problem
  and, with `auth sufficient`, fell through to `pam_unix` then `pam_deny`. It
  now treats a `valid:false` verdict as a normal negative result: the reason is
  surfaced, authentication fails with `PAM_AUTH_ERR`, and rate-limiting/CrowdSec
  reporting run as intended. The verify-response parser was extracted
  (`ob_parse_verify_response`) and is now covered by unit tests.

### Removed

- **`nscd` is no longer a dependency.** The NSS module keeps its own in-memory
  and cross-process on-disk cache (`/var/cache/nss_llng`), so a separate
  name-service cache daemon adds nothing: it only interposes a second cache in
  front of one that already exists. `nscd` is also deprecated upstream and
  absent from modern distributions (Fedora builds glibc with `--disable-nscd`
  and dropped the package; other distributions have followed, superseding it
  with `systemd-resolved` and SSSD), so requiring it made the package harder to
  install rather than safer. The `Depends:` (Debian) and `Requires:` (RPM) are
  dropped, the demo/quick-start Docker environments no longer install or start
  it, and the documentation no longer instructs restarting it. Existing hosts
  are left alone: with the dependency gone, `apt autoremove` reclaims `nscd` if
  nothing else wants it, and an administrator who runs it deliberately for
  `hosts`/`services` keeps it. (Historically `nscd` also crashed with `SIGABRT`
  in this module's NSS path; that was a double-free in the module itself and
  was fixed in 0.6.1 — it is no longer a reason to avoid `nscd`, only the
  reason the redundancy was noticed.)
- **The PAM module now invalidates the NSS module's own file cache.** It removes
  the entries directly (by name, and by uid for newly created users), so user
  and group-membership changes stay visible immediately. Entries are removed
  with `unlinkat()` relative to directory file descriptors opened `O_NOFOLLOW`
  and verified root-owned, so no path component can be swapped for a symlink.
  The `nscd --invalidate passwd group` fork is **kept as well**, best-effort,
  on hosts where `/usr/sbin/nscd` exists: this release does not disable `nscd`
  on upgraded hosts, and where it still runs, glibc routes both `passwd` and
  `group` through it. The module implements `passwd` only, so without that fork
  a removal from `open-bastion-sudo` would have stayed cached by `nscd` for
  `positive-time-to-live group` (3600 s on Debian) — turning an immediate sudo
  revocation into a delay of up to an hour. Hosts without `nscd` installed pay
  nothing: no binary, no fork.

### Changed

- **Resilience to an LLNG outage no longer depends on `nscd`, and the buffer is
  shorter.** `nscd`'s persistent cache, combined with its `reload-count`,
  effectively re-served known users for the length of an outage. The NSS
  module's own cache expires at `cache_ttl` (default **300 s**) and never
  serves stale data: an expired file-cache entry is deleted on read, and a
  transient LLNG failure returns `NSS_STATUS_UNAVAIL` rather than falling back
  to the expired entry. On a host where LLNG becomes unreachable, `getent
  passwd <user>` therefore stops resolving roughly `cache_ttl` after the last
  successful lookup, and `sshd` can no longer map the user. Sites that want a
  longer buffer should raise `cache_ttl` in
  `/etc/open-bastion/nss_openbastion.conf` (accepted range 0–86400 s); see
  "NSS cache and LLNG outages" in the admin guide for the trade-off against
  how quickly a deprovisioned user disappears.
- **Only root can refill the NSS cache, which is now visible in normal
  operation.** The module authenticates to LLNG with the root-only server
  token, so an unprivileged process can never query the portal and reads the
  file cache alone. With `nscd` gone there is no other refresher: an entry that
  expires while no root process happens to resolve that user is simply not
  renewed. In a long idle SSH session, past `cache_ttl` since the last
  root-side lookup, `ls -l` falls back to numeric uids, `whoami`/`id` fail, and
  an outgoing `ssh`/`scp` refuses with `You don't exist, go away!`. Any
  root-side lookup — a new session, `su`, `sudo`, a `cron` job — repairs it at
  once, and authentication and authorization are unaffected; this is a
  nuisance, not a lockout. Documented under "Who refreshes the cache" in the
  admin guide, with `cache_ttl` and a periodic root lookup as mitigations. A
  proper fix (a socket-activated root refresher like `ob-cert-daemon`, or a
  refresh driven by `ob-heartbeat`) is not implemented yet.
- **A lookup for a user that does not exist now reaches LLNG on every
  attempt.** Negative results are cached in memory only, per process, and the
  on-disk cache is written on success only — deliberately, since it is
  populated from an unauthenticated path (`sshd` resolves the login name before
  authenticating) and letting that path create files would let a remote client
  fill `/var/cache/nss_llng` with inodes. Since `sshd` forks per connection,
  each SSH attempt with an unknown username costs one HTTPS `/pam/userinfo`
  request, triggerable by an unauthenticated remote client. `nscd` only
  partially covered this before: its negative cache is keyed per name
  (`negative-time-to-live passwd`, 20 s), so it absorbed a flood repeating one
  username and did nothing against a flood of distinct ones. Bound it where
  connection floods are already bounded — `MaxStartups`, `fail2ban`/CrowdSec —
  as described under "Lookups for users that do not exist" in the admin guide.

### Known issues

- **SELinux in `enforcing` mode (Rocky/RHEL/AlmaLinux) is untested with the
  on-disk cache.** An NSS module runs inside the calling process, so the cache
  is written from `sshd_t`, `sudo_t`, `crond_t` and friends rather than from a
  daemon of its own. If the default policy denies those domains a write under
  `/var/cache/nss_llng`, the write fails silently (a failed cache write is
  non-fatal by design) and the cross-process cache is never populated on RPM
  hosts — which would make the root-only-refresh regime above the normal state
  rather than an edge case. This has **not** been verified on Rocky 9
  enforcing, and no policy module ships with the RPM. The admin guide gives the
  `ausearch`/`audit2allow` check to run before deploying there, and a sketch of
  the policy module such a host would need.

## [0.6.2] - 2026-06-25

Hotfix for 0.6.1: the Debian package failed to install/upgrade.

### Fixed

- **0.6.1 package configuration no longer aborts in `postinst`.** A comment in
  the `open-bastion` postinst contained the literal debhelper substitution
  token. debhelper substitutes that token wherever it appears — including inside
  the comment — so the trailing words of the comment ended up on their own line
  and were executed as a command (`so: not found`, exit 127). Every 0.6.1
  install/upgrade therefore failed at `configure`, leaving the package
  half-configured. The comment no longer contains the token; the assembled
  postinst is syntax-checked. Upgrading to 0.6.2 completes configuration and
  repairs a host left half-configured by 0.6.1 (`apt -f install` /
  `dpkg --configure -a` also recover once 0.6.2 is available).

## [0.6.1] - 2026-06-25

Maintenance release: fixes a long-running-process crash in the NSS module and
keeps already-configured bastions working across plain package upgrades.

### Fixed

- **The NSS module no longer crashes a long-lived caching consumer (e.g.
  `nscd`).** `cache_find()` / `cache_find_by_uid()` freed an expired in-memory
  cache entry's password buffer but left the pointer dangling; once the cache
  reached capacity, the LRU eviction in `cache_add()` freed it a second time,
  aborting the host process with a glibc `double free or corruption` (SIGABRT).

- **`apt upgrade` no longer breaks an already-configured bastion.** The
  socket-activated bastion helpers — `ob-cert.socket` (hop-certificate minting
  for `ob-ssh`/`ob-scp`) and `ob-record.socket` (the session-recording sink) —
  ship `--no-enable`/`--no-start`, since the package can't know a host's role;
  `ob-bastion-setup` is what enables them. A plain package upgrade therefore left
  them inactive, and because recording is fail-closed every login was then
  refused (`recording sink unreachable; access refused`). The `postinst` now
  re-asserts both sockets on `configure`, idempotently, **only** when the host is
  already a bastion (the `ob-bastion-setup` sshd drop-in is present) and only
  enables `ob-record.socket` when session recording is on. Backends and
  unconfigured hosts are untouched. Re-running `ob-bastion-setup` remains the
  documented recovery and is no longer required merely to survive an upgrade.

## [0.6.0] - 2026-06-22

New bastion file-transfer and remote-command paths, declarative service accounts,
and automatic session-recording retention. `ob-ssh` gains one-shot backend
commands, `ob-sftp` joins `ob-ssh`/`ob-scp`, `ob-builder` can bake in
SSH-key-only service accounts, and `ob-session-prune` bounds the recordings
store. Includes a `-c CIPHER` passthrough fix for `ob-scp`/`ob-sftp` and a
progressive-discovery documentation reorganization.

### Added

- **`ob-ssh` can run a one-shot command on the backend.** A trailing command is
  now forwarded to the backend (`ob-ssh backend uptime`) and run
  non-interactively — no pty, output captured verbatim, like `ssh host cmd` —
  instead of being mis-read as a port (`Bad port '...'`). New `-p`/`--port`,
  `-l`/`--login` and `-o` (ssh option passthrough) flags, plus `--` to end
  option parsing; the legacy positional `[port]` still works. Works in both
  direct and `ForceCommand` modes. From a workstation whose `ssh_config` sets
  `RemoteCommand ob-ssh ...`, override it to append the command:
  `ssh -o RemoteCommand="ob-ssh 10.0.0.5 ls -la" backend1` (ssh forbids
  combining a command-line command with a configured `RemoteCommand`).
- **`ob-sftp` bastion file-transfer connector.** The `sftp` counterpart of
  `ob-ssh` / `ob-scp`: run on a bastion, it mints a short-lived,
  LLNG-signed certificate (via the shared `ob-cert-lib.sh`) and opens an
  interactive or batch SFTP session to a backend — no user SSH key on the
  bastion and no agent forwarding. Connects to a single endpoint
  (`[user@]backend[:path]`); options after the connector's own flags pass
  straight through to `sftp(1)`. See `ob-sftp(1)`.
- **`ob-builder` can declare service accounts.** The builder now collects
  SSH-key-only local accounts (ansible, backup, CI/CD, …) — interactively or via
  a `service_accounts:` list in the `--config` YAML — validates each entry
  (name, `SHA256:`/`MD5:` fingerprint, absolute shell/home) at build time, and
  bakes them into both outputs: the shell installer writes
  `/etc/open-bastion/service-accounts.conf` (`0600 root:root`) and the Ansible
  role carries them as `ob_service_accounts_content` (overridable per
  host/group). `service_accounts_file` is set in the generated
  `openbastion.conf`. No PAM-module change — `src/service_account.c` already
  parses that file. See `doc/service-accounts.md` and `ob-builder(1)`.
  Validated end-to-end on a Mode E VM (`local-test/deploy-shell.sh`). ob-builder
  warns when an account would be unusable on the target: a `home`/`shell` outside
  the approved lists (silently dropped by the PAM module) or a missing fixed
  `uid`/`gid` (NSS cannot resolve it for sshd's pre-auth lookup, so it is
  unreachable over SSH unless it already exists locally). `doc/service-accounts.md`
  documents these requirements (including not reusing a system username).
- **Session-recording retention (`ob-session-prune`).** A new daily timer
  (`ob-session-prune.timer`, enabled at install) bounds the recordings store,
  which matters because recording is fail-closed — a full disk refuses new
  logins. It compresses closed recording payloads older than
  `recording_compress_after_days` (default 1; typescripts compress ~10–20×,
  the `.json` index is left readable) and deletes recordings older than
  `recording_retention_days` (default 365; `0` keeps them forever). Expiry is
  logged at `notice` level since it drops audit evidence. Runs as root from a
  sandboxed oneshot service and only writes under
  `/var/lib/open-bastion/sessions`, preserving the tamper-evident layout. See
  `doc/session-recording.md` and `ob-session-prune(8)`.

### Fixed

- **`ob-scp` / `ob-sftp` no longer shadow `scp`/`sftp`'s own `-c CIPHER`.** Their
  config option is now long-only (`--config`); a short `-c` used to be consumed
  as the config path, so `ob-scp -c aes256-gcm@openssh.com …` never reached
  `scp`. Other options (`-p`, `-P PORT`, `-r`, `-b FILE`, `-l`, …) already passed
  through and still do; use `--` to end ob-\* option parsing explicitly.

### Documentation

- Docs reorganized for progressive discovery.
- Service-account security model documented.
- Backend access guidance corrected.
- Retention guidance.

## [0.5.1] - 2026-06-17

Server-token resilience and session-visibility fixes: bastions no longer silently
lose their bastion voucher (and sudo) overnight, and SSH sessions are visible to
`who`/`w`/`loginctl` again.

> **Upgrade note.** After upgrading, **re-run `ob-bastion-setup` /
> `ob-backend-setup`** (or `ob-standalone-setup`) so the regenerated
> `/etc/pam.d/sshd` registers sessions with `systemd-logind` and the heartbeat
> timer is armed. On an already-enrolled host you are not re-running, just arm
> the timer once: `systemctl enable --now ob-heartbeat.timer`.

### Fixed

- **`ob-heartbeat.timer` is now armed at enrollment.** The timer ships with
  `ConditionPathExists=/var/lib/open-bastion/token`, but the package's
  install-time `systemctl start` runs _before_ enrollment writes that token, so
  the condition was false and the timer was silently skipped — it only armed on
  the next reboot (an ordering race: hosts enrolled before the package was
  (re)configured were fine, the usual "install then enroll" order was not).
  Until then the short-lived server token expired with nothing to refresh it,
  and `pam_openbastion` fell back to its offline cache: a bastion login still
  succeeded but minted **no bastion voucher** (`ob-ssh` failed with
  `LLNG_BASTION_VOUCHER is unset`) and `sudo` locked out (`server token invalid
or expired`). `ob-enroll`, `ob-bastion-setup` and `ob-backend-setup` now
  `systemctl enable --now ob-heartbeat.timer` once the token is in place.
- **Cert-hop SSH sessions are visible to `who` / `w` / `loginctl` again (#150).**
  The generated `/etc/pam.d/sshd` omitted `pam_systemd`, so sessions were never
  registered with `systemd-logind` and were invisible to session tooling — and
  to `ob-heartbeat`'s connected-users report, which reads `loginctl`/`who`.
  `who am i` was empty and `sudo su` surfaced only `root`. Both setups now add
  `session optional pam_systemd.so` to the sshd session stack, emitted only when
  the module is installed (mirroring how distros tie the line to
  `libpam-systemd`).

### Changed

- **The server access token is now refreshed on demand.** On a `401` from
  `/pam/verify` or `/pam/authorize` (expired server token), `pam_openbastion`
  refreshes the token via `/pam/heartbeat` — which preserves the per-device
  `bastion_id`, unlike the OIDC `/oauth2/token` grant — persists it, and retries
  once **before** any offline fallback. A fresh login is therefore self-healing
  even if the heartbeat timer lapsed, instead of silently degrading to an
  unvouched offline session.

## [0.5.0] - 2026-06-16

Tamper-evident session recording — a non-root user can no longer delete or alter
its own session recordings — plus `sudo -i` and backend `sudo` fixes.

> **Upgrade note (session recording).** Recording now streams to a root,
> socket-activated sink (`ob-record-sink`) instead of being written by the user.
> After upgrade, **re-run `ob-bastion-setup`** (or `ob-standalone-setup`) so it
> enables `ob-record.socket`, sets `/var/lib/open-bastion/sessions` to
> `root:ob-sessions 0750`, and migrates any legacy per-user dirs to root
> ownership. Recording is **fail-closed** when enabled: if `ob-record.socket` is
> not active, recorded logins are refused. `ForceCommand` now points directly at
> `ob-session-recorder` (the setgid `ob-session-recorder-wrapper` is removed).

### Added

- **Tamper-evident session recording (#151).** Sessions are now streamed to a
  root, systemd socket-activated sink (`ob-record-sink`) instead of being written
  by the user-side recorder. The sink derives the recorded user from the
  connection's `SO_PEERCRED` (kernel-verified) and writes the recording +
  metadata **root-owned** under `/var/lib/open-bastion/sessions/<user>/`
  (`root:ob-sessions 0750`, files `0640`). The recorded user is not in
  `ob-sessions`, so it can no longer list, read, delete or truncate any
  recording — including its own. The recorder reaches the sink through the new
  unprivileged `ob-record-connect` connector (a POSIX shell cannot open an
  `AF_UNIX` socket). Recording is **fail-closed**: if the sink is unreachable the
  session is refused rather than falling back to a user-deletable file.
  Because the recorder runs on the bastion, a user who is root on a backend does
  not escape recording. New units `ob-record.socket` / `ob-record@.service`.
  Drops R-S18 to P=1 (see `doc/security/99-risk-reduce.md`).

### Changed

- **The setgid `ob-session-recorder-wrapper` is removed.** It created the
  user-owned per-user recording directory that made recordings deletable; with
  the root sink it is obsolete. `ForceCommand` now points directly at
  `ob-session-recorder`, and `/var/lib/open-bastion/sessions` is
  `root:ob-sessions 0750` (was `3771` setgid+sticky). `ob-bastion-setup` enables
  `ob-record.socket` and migrates any legacy user-owned per-user dirs to root
  ownership.

### Fixed

- **`sudo -i` is authorized again on bastions (#152).** `sudo -i` runs under the
  PAM service name `sudo-i`; `pam_openbastion` forwarded it verbatim to LLNG,
  whose pam-access plugin only knows `ssh`/`sshd`/`sudo` and default-denied the
  rest — so `sudo -i` failed at PAM account management while `sudo`/`sudo su`
  worked. The module now canonicalizes `sudo-i` to `sudo` (self-contained in the
  bastion; no plugin change required).
- **Backend `sudo` works for SSO users (#154).** `ob-backend-setup` configured
  the PAM side of sudo but never created the `open-bastion-sudo` group nor the
  `/etc/sudoers.d/open-bastion` rule, so an LLNG-authorized user still got "not
  in the sudoers file". It now provisions both (mirroring `ob-bastion-setup`,
  `visudo`-validated).
- **Debian package ships the socket-activation template units.** `dh_installsystemd`
  does not auto-install named `@.service` templates, so `ob-cert@.service` and
  `ob-record@.service` were missing from the `.deb` — the sockets could not spawn
  an instance ("Connection refused"). Both templates are now installed. (This was
  a latent gap for `ob-cert@.service` too.)
- **RPM GPG signature check (#99).** Release RPMs are signed with the native EL
  `rpm` so the signature verifies.

## [0.4.1] - 2026-06-16

Decouples bastion hop-certificate minting from the interactive `sudo` policy,
which was breaking `ob-ssh`/`ob-scp` in max-security (Mode E).

> Requires the matching `pam-access` LemonLDAP::NG plugin update: `/pam/bastion-cert`
> and `/pam/bastion-token` no longer require the caller's server group to be a
> configured bastion group. The `(bastion_id, user)` voucher is the sole control
> (it is minted by `/pam/authorize` only for a host in `pamAccessBastionGroups`),
> so a single project-wide OIDC `client_id` works with finer-grained PAM groups
> inside the project.

### Changed

- **Bastion cert minting no longer goes through `sudo`.** The old
  `ob-bastion-cert-helper` + NOPASSWD sudoers bridge is replaced by
  `ob-cert-daemon`, a socket-activated service (runs as root) reached through the
  new unprivileged `ob-cert-request` client. The daemon derives the
  certificate's user from the connection's `SO_PEERCRED` (kernel-verified, never
  from the request), so a caller can still only mint a certificate for itself,
  and the root-only server token never leaves the daemon. This decouples machine
  certificate minting from the interactive sudo policy — in Mode E the sudo PAM
  stack required an LLNG token, which broke `ob-ssh`/`ob-scp` hops. No sudo, no
  setuid. `ob-bastion-setup` now enables `ob-cert.socket` instead of installing a
  sudoers drop-in (and removes the obsolete one on upgrade). Request inputs are
  bounded and a connection timeout prevents a stalled peer from pinning a
  per-connection process.

## [0.4.0] - 2026-06-16

Completes the certificate-based bastion→backend hop: `ob-ssh` and `ob-scp` now
work end to end on OpenSSH 9.8+ (Debian 13, etc.), and the session recorder no
longer hides command exit codes.

> Requires the matching `pam-access` LemonLDAP::NG plugin: the cert
> `source-address` pin is now opt-in (`pamAccessBastionCertPinSourceAddress`,
> off by default), and each ephemeral hop certificate's fingerprint is
> registered so the backend's `/pam/authorize` fingerprint binding accepts it.

### Fixed

- **`ob-ssh` / `ob-scp` bastion→backend hop works end to end.** The per-session
  `LLNG_BASTION_VOUCHER` and the onward ephemeral certificate never reached the
  backend on OpenSSH >= 9.8: each connection runs as **two** processes named
  `sshd-session` (the privileged monitor and an unprivileged child), and the
  SSH-fingerprint spool writer (`ob-ssh-principals`) and the `pam_openbastion`
  reader keyed the spool on different PIDs, so the fingerprint was never
  recovered and the hop fell back to a no-cert authorize. The bastion helper,
  the backend helper and `pam_openbastion` now all converge on the **outermost
  contiguous `sshd-session`** (the monitor), with an `sshd` fallback for pre-9.8
  OpenSSH (RHEL/Rocky 9). `/run/open-bastion` is created `0711` (traversable by
  the `nobody` principals helper, not listable) so the spool can actually be
  written.
- **`ob-session-recorder` no longer hides command failures.** As the bastion
  `ForceCommand` it wrapped commands in `script(1)` without `-e`, so any
  non-interactive command through a bastion (`ob-ssh` / `ob-scp` hops, scripted
  `ssh`, CI jobs) reported success even when it failed, and the recorded session
  status was always `completed`. It now uses `script -e` (util-linux >= 2.31:
  Debian 11+, RHEL/Rocky 8+) so the child's exit status propagates; older
  `script` falls back to the previous behaviour.

### Security

- The SSH-fingerprint spool parent `/run/open-bastion` is `0711` (traverse-only,
  not world-listable) on both bastion and backend, and the `ob-enroll`
  device-state file is `0600` (it now lives in the traversable
  `/run/open-bastion`, so it is locked down by its own mode).

## [0.3.2] - 2026-06-16

Bug-fix release: Mode E privilege escalation now behaves as documented —
`sudo` and `sudo -i` require a fresh LLNG token — plus an `ob-builder` Mode E
deploy fix surfaced while validating the above on a full VM lab.

### Fixed

- **Mode E `sudo` requires the LLNG token again (no longer passwordless).** On a
  bastion the PAM module runs in `authorize_only` mode (the SSH certificate has
  already authenticated the user for sshd), but that setting also applied to the
  `sudo` PAM stack, where there is no prior certificate auth — so `sudo`
  silently succeeded without ever asking for a token, defeating the Mode E
  guarantee. `pam_openbastion` now always enforces the token for the `sudo` /
  `sudo-i` PAM services regardless of `authorize_only`. Fixed in the module, so
  it covers bastion, backend and standalone in every mode.
- **`sudo -i` works for SSO users.** `sudo` 1.9 uses a separate `sudo-i` PAM
  service that `ob-bastion-setup` / `ob-backend-setup` never configured, so
  `sudo -i` fell back to the distro default (`pam_unix`) and failed for NSS-only
  SSO users with _"account validation failure, is your account locked?"_. Every
  function that writes `/etc/pam.d/sudo` now also writes `/etc/pam.d/sudo-i`
  with the same stack.
- **`ob-builder` Mode E roles always ship the KRL file.** A Mode E Ansible role
  failed to deploy with _"Could not find open-bastion-krl"_ whenever the
  portal's KRL was still empty (a fresh portal with no revocations): the role's
  mandatory _Deploy KRL_ task referenced `files/open-bastion-krl`, but the
  emitter only wrote it when the fetched KRL was non-empty. It now always ships
  the file (an empty KRL is valid; the refresh cron fills it later).

### Added

- **`ob-standalone-setup`** — a symlink to `ob-bastion-setup` installed for
  clarity. Invoked under that name it defaults `--node-role` to `standalone`; an
  explicit `--node-role` still overrides it.

### Documentation

- Documented the full **`pam-access` OIDC Relying Party** setup in
  `doc/llng-configuration.md`: the required options
  (`AllowDeviceAuthorization`, `DeviceOwnership = organization`,
  **`AllowOffline = 1`**), the `offline_access` scope, and the
  offline-refresh-token gotcha (needs `oidc-device-organization` >= 0.3.3, or
  the device flow returns a non-renewable token and enrollment fails in
  Mode E). Referenced as a prerequisite from all three quick-starts (Docker,
  Ansible, shell).

## [0.3.1] - 2026-06-15

Maintenance release: `ob-heartbeat` now reports fleet visibility data
("who is connected", client version, node role) to the SSO, plus
robustness fixes for enrollment and the `ob-builder` Ansible artefacts
surfaced while deploying a Mode E bastion.

### Added

- **`ob-heartbeat` reports the connected users** ("who is connected on this
  machine") to the SSO in each beat: a `sessions` array of
  `{user, from, tty, since}`, collected via `loginctl` (with a `who(1)`/utmp
  fallback when systemd-logind is unavailable). Two new config keys:
  `report_sessions` (default `true`; the list is privacy-sensitive and can be
  disabled) and `max_reported_sessions` (default 200, caps the payload). The
  pam-access plugin stores it per machine as `_pamSessions` / `_pamSessionCount`
  (requires the matching LLNG plugin).
- **`ob-heartbeat` reports the open-bastion client version and the node role**
  (`node_role`: `bastion` | `standalone` | `backend`). `ob-bastion-setup` /
  `ob-backend-setup` gained `--node-role` (validated, written to
  `openbastion.conf`), and the shell installer forwards the builder's target
  role so standalone hosts are recorded correctly. Stored server-side as
  `_pamVersion` / `_pamNodeRole`.
- **Ansible quick-start for the shell installer** and documentation of the SSH
  connection variables (`ansible_host` / `ansible_user` /
  `ansible_ssh_private_key_file` / `ansible_become`, plus the
  `IdentitiesOnly=yes` tip) in the example inventory.

### Fixed

- **`ob-enroll` now fails when `offline_access` was requested but no
  `refresh_token` is issued.** It removes the unrenewable token and exits
  non-zero with actionable guidance, instead of saving a token that would let
  NSS/SSO work for ~1 h and then break (`ob-*-setup` only choked later, and the
  dead token was reused on the next run). A refresh-less token is still accepted
  when `offline_access` was not requested.
- **`ob-builder`: dropped a duplicate `ob_verify_ssl` key** in the generated
  Ansible defaults, which triggered Ansible's "duplicate mapping key" warning on
  every run.
- **Ansible role: the `Restart sshd` handler runs only when `ob_auto_setup` is
  false** (`| bool`-cast so `--extra-vars` string overrides behave). With
  `ob_auto_setup: true`, `ob-*-setup` already restarts sshd, and Mode E locks
  `sudo` behind an LLNG token — so a `become` handler flushed afterwards failed
  with "Missing sudo password" on an otherwise-successful deploy.
- **`ob-heartbeat`: hardened session collection** — validate
  `max_reported_sessions` (fall back to 200 on a non-integer), fall back to
  `who(1)` when `loginctl` exists but `list-sessions` fails (containers/chroots
  without logind), and fix the man page OPTIONS to match the script.

## [0.3.0] - 2026-06-13

Headline: **certificate-based bastion→backend vouching** replaces the
previous `LLNG_BASTION_JWT` / `SendEnv` mechanism, which was structurally
broken (a `SendEnv`/`AcceptEnv` variable only ever reaches the eventual child
process environment, never the PAM environment `pam_getenv` reads, so a backend
with `bastion_jwt_required=true` rejected every session). The bastion now
vouches for each hop by obtaining a short-lived, LLNG-signed SSH user
certificate; backends validate it natively. Also bundles the token-lifecycle,
NSS, sshd-lockdown and session-recorder fixes, and makes the `ob-builder`
artefacts (Ansible role and shell installer) deploy fully unattended.

### Added

- **Certificate-based bastion→backend vouching.** `ob-ssh` (on the bastion)
  generates an ephemeral keypair in tmpfs and asks LLNG to sign it
  (`POST /pam/bastion-cert`, authorised by the bastion's device-grant server
  token plus a per-`(bastion_id, user)` voucher proving the user actually
  connected to _this_ bastion). The resulting ~120 s user certificate carries
  `principal = user`, a `bastion=<id>;user=<u>;target=<host>` key-id and a
  `source-address` critical option. The backend's sshd validates it against the
  LLNG CA (`TrustedUserCAKeys`) and refuses it off-bastion (source-address),
  while an `AuthorizedPrincipalsCommand` enforces the `allowed_bastions`
  allowlist from the cert key-id. No agent forwarding and no user key on the
  bastion are required. See `doc/bastion-architecture.md` and
  `doc/design/bastion-cert-vouching.md`.
- **`ob-scp`**: bastion file-copy counterpart of `ob-ssh`. Copies files
  bastion→backend, backend→bastion, or backend↔backend using a short-lived
  vouched certificate. All transfers are forced through the bastion (`scp -3`)
  so the connection's source address matches the certificate's pinned address
  (a direct backend-to-backend transfer would be rejected). All remote
  endpoints must share the same remote user (one vouched certificate = one
  principal).
- **Ansible quick-start guide** (`doc/ansible-quickstart.md`): generate the
  bastion + backend roles with `ob-builder`, declare hosts and their IPs in an
  inventory, and apply with `ansible-playbook` (including unattended
  device-code auto-approval via an LLNG cookie). Linked from the main README,
  which now points at the two quick-starts (Docker try-it and Ansible fleet)
  instead of inlining a third.

### Changed

- **`ob-ssh-proxy` renamed to `ob-ssh`.** The bastion-to-backend connector is
  now `ob-ssh`; the certificate-minting logic it shares with the new `ob-scp`
  was factored into a sourced library, `ob-cert-lib.sh` (installed under
  `/usr/lib/open-bastion/`).
- **Server token relocated from `/etc/open-bastion/token` to
  `/var/lib/open-bastion/token`.** The token is runtime state (refreshed every
  few minutes by `ob-heartbeat`), not configuration, so per the FHS it belongs
  under `/var/lib`. This also lets the `ob-heartbeat.service` sandbox keep
  `/etc` fully read-only (`ProtectSystem=strict`) instead of having to leave
  `/etc/open-bastion` writable. Upgrades migrate automatically: the Debian
  `postinst` / RPM `%post` move an existing token and repoint
  `server_token_file` / `SERVER_TOKEN_FILE` in the deployed config files. The
  path remains configurable via `server_token_file`.
- **`ob-heartbeat` renews the access token from the offline refresh token.**
  The server is enrolled with an `offline_access` grant; the timer (every
  5 min, below the access-token lifetime) refreshes the short-lived access
  token so NSS resolution and authorization keep working — previously the
  access token could lapse (e.g. overnight) and `getent passwd` went empty.
- **`ob-builder` artefacts deploy fully unattended.** The generated Ansible role
  and self-extracting shell installer now run `ob-{bastion,backend}-setup`
  non-interactively end to end: they pass `--client-id` and `--yes` (setup
  otherwise aborted on a "Missing --client-id" / a `[y/N]` prompt), pass
  `--insecure` when `verify_ssl` is false (an http test portal was otherwise
  rejected), the shell installer forwards `--allowed-bastions`, and the Ansible
  role gained `ob_approve_base_url` / `ob_approve_host` overrides for
  controller-side device-code approval in split-horizon / NAT topologies.
  `ob-builder` also fails fast when neither `--output-shell` nor
  `--output-ansible` is given, and validates `allowed_bastions` against a safe
  character set before embedding it.

### Removed

- **The bastion-JWT transport and its verification subsystem.** The
  `bastion_jwt_*` configuration keys and the `AcceptEnv LLNG_BASTION_JWT` sshd
  directive are gone, along with the in-module JWT verifier (and its JWKS / JTI
  caches). They are replaced by the certificate vouching above; the
  "accept only this bastion" policy is now `ob-backend-setup --allowed-bastions`
  writing `/etc/open-bastion/allowed_bastions`. Existing configs still load
  (the removed keys are silently ignored). The unrelated `client_secret_jwt`
  OIDC client-assertion authentication is unaffected.

### Fixed

- **`ob-ssh` interactive sessions: double echo, and Ctrl-C / a failing command
  tearing down the connection.** The connector relied on ssh's TTY
  auto-detection when re-originating to the backend, which is fragile across a
  bastion-pty → backend-pty hop and could leave the bastion-side terminal in
  cooked mode (input echoed twice) and deliver signals to the connector instead
  of the remote shell. `ob-ssh` now controls TTY allocation explicitly: `-tt`
  when stdin is a terminal (so the bastion-side tty goes raw — single echo, and
  Ctrl-C / failures act on the remote shell), `-T` otherwise.
- **NSS module kept serving a stale access token after rotation.**
  `libnss_openbastion` loaded the server token once per process and never
  re-read it, so once `ob-heartbeat` rotated the token the cached value
  expired and the portal answered `401`. That was treated as
  "user not found", poisoning the (nscd) negative cache and breaking
  `getent passwd` / SSH logins roughly once per access-token lifetime until
  the resolver was restarted. The module now reloads the token when its mtime
  changes and distinguishes an authoritative "not found" from a transient
  error (HTTP ≠ 200 / curl failure): transient errors trigger a reload+retry
  and return `EAGAIN` / `NSS_STATUS_UNAVAIL` instead of being cached as a miss.
- **sshd hardening drop-in could be silently overridden by cloud-init.** Cloud
  images ship `/etc/ssh/sshd_config.d/50-cloud-init.conf` with
  `PasswordAuthentication yes`, and sshd keeps the _first_ value seen while
  `Include` expands the drop-in directory alphabetically. The open-bastion
  drop-in was written as `50-open-bastion-{bastion,backend}.conf`, which sorts
  _after_ `50-cloud-init.conf`, so password authentication stayed enabled on
  freshly provisioned bastions and backends. `ob-bastion-setup` /
  `ob-backend-setup` now write `00-open-bastion-{bastion,backend}.conf` (and
  remove the legacy `50-` file on rerun) so the cert-only lockdown wins.
- **Session recording aborted the session on a fresh install.** The per-user
  recording lives under `/var/lib/open-bastion/sessions/`, but the recorder runs
  as the connecting user (its `ob-sessions` gid is dropped before exec) and
  could not traverse into its own subdir. The Debian `postinst` / RPM `%post`
  now create `/var/lib/open-bastion` as `711` and `sessions/` as `3771`
  (setgid + sticky + o+x, no o+r) so the de-privileged recorder can traverse
  without being able to list other users' sessions.
- **`ob-heartbeat` could not rewrite the access token** under its own sandbox
  (the path was effectively read-only), so token renewal silently failed.
- **`ob-bastion-id` hit a 403** fetching the bastion identity; it now uses the
  probe mode of `/pam/bastion-token`.

### Security

- Refreshed threat model for the cert-vouching + heartbeat model
  (`doc/security/`). "Only this bastion" is enforced defence-in-depth, both by
  the certificate `source-address` critical option (sshd-native) and the
  `bastion_id` allowlist parsed from the cert key-id by `pam_openbastion`.

## [0.2.3] - 2026-05-23

Tooling release: ships a new admin builder for fleet deployments
(`open-bastion-builder`), a small helper to discover bastion identities
(`ob-bastion-id`), and an Ansible role with opt-in device-code
auto-approval. The PAM/NSS modules themselves are unchanged on the
wire — only operator-side ergonomics and packaging.

### Added

- **`open-bastion-builder`** (new admin-side package): interactive Bash
  CLI `ob-builder` that asks a short questionnaire (security scenario,
  SSO URL, OIDC client_id / client_secret policy, server group, target
  role, optional bastion whitelist, optional Ansible auto-approve) and
  emits either a self-extracting shell installer or an Ansible role
  (or both). The generated artefact configures the open-bastion package
  on target servers against an LLNG SSO without ad-hoc per-host
  scripts. Ships its own `.deb` / `.rpm`, distributed separately from
  the runtime package so the builder is only installed on admin
  workstations. See `admin-builder/README.md`.

- **`ob-bastion-id`**: small utility that runs on an enrolled bastion,
  requests a JWT from LLNG's `/pam/bastion-token`, decodes it and
  prints the `bastion_id` claim.

- **Ansible auto-approval of the OIDC Device Authorization Grant**:
  the generated Ansible role can drive LLNG's `/device` endpoint with
  a session cookie obtained ahead of time via the `llng` CLI from
  `simple-oidc-client`, automating the per-host browser approval that
  required by RFC 8628. Opt-in at build time; the cookie is asked for via
  `vars_prompt` at every play run and is never persisted.

- **`ob-enroll`**: new `OB_ENROLL_STATE_FILE` env var. When set,
  `ob-enroll` writes `{user_code, verification_uri, portal_url,
interval}` to that file as soon as LLNG returns the device-grant
  initiation, then continues polling. External orchestrators
  (notably the new Ansible auto-approve flow) can read this file
  to drive the approval while `ob-enroll` is still polling. The
  file is removed on successful enrolment.

### Changed

- **Docker demo images** (`docker-demo-{cert,token,maxsec,token-svc}/`):
  all 10 build Dockerfiles now use `cmake -DCMAKE_INSTALL_PREFIX=/usr
... && make install` instead of per-Dockerfile allowlists of
  `cp ../scripts/ob-X` lines. New ob-\* scripts added to `CMakeLists.txt`
  automatically land in the demo containers; no per-Dockerfile
  maintenance needed.

- **Debian packaging**: `debian/{config,templates,postinst,postrm}`
  renamed to `debian/open-bastion.{config,templates,postinst,postrm}`
  to disambiguate now that three binary packages are produced
  (`open-bastion`, `open-bastion-desktop`, `open-bastion-builder`).
  `debian/*.install` files dropped the redundant `debian/tmp/` prefix.

### Fixed

- **`ob-enroll`** no longer overrides the bash positional `set -e` due
  to `[ ... ] && X` chains at the end of `_load_config_yq`,
  `_load_config_awk`, `run_outputs_for_role` and `main` — these
  silently exited the process when their trailing test was false.
  All four functions now end with an explicit `return 0`.

- **`open-bastion-builder` (security)**: embedded client_secret is now
  stored base64-encoded in the generated shell installer so that a
  secret containing shell meta-characters (`$`, `` ` ``, `"`, `\`) can
  no longer break out of the bash literal and achieve command
  execution as root at install time. Tightened `is_valid_url` for the
  same reason. Conf-file substitution at install time switched from
  `sed` (which used `|` as a delimiter without escaping) to bash
  native `${var//pattern/repl}`.

- **`make install`** ships `config/openbastion.conf.example`,
  `config/service-accounts.conf.example`, the hardening / audit
  templates under `/usr/share/open-bastion/`, `README.md`, and the
  man pages, instead of leaving them out of the install set.

## [0.2.2] - 2026-05-21

Robustness release for the setup scripts and the session recorder. The
previous setup could brick a fresh bastion in several non-obvious ways
(failed enrollment + applied SSH/PAM lockdown, silently broken NSS,
PAM module rejecting its own generated config) and the ForceCommand
recorder broke scp / sftp / rsync. None of this changes the on-wire
protocol with LemonLDAP::NG — only the install path and the recorder
behaviour are affected.

### Fixed

- **`ob-bastion-setup`**: no longer locks down SSH/PAM before server
  enrollment has succeeded. Added a pre-flight check on
  `POST /oauth2/device` and reorganised `main()` into three phases:
  inert preparation → portal pre-flight + enrollment → SSH/PAM
  lockdown. In `--max-security`, enrollment failure is now FATAL and
  the script aborts before touching `/etc/ssh/sshd_config*`,
  `/etc/pam.d/sshd`, `/etc/pam.d/sudo`, etc. Inert files written
  during phase 1 are rolled back from `BACKUP_DIR` (or removed if
  no backup existed), so a failed run leaves the system unchanged.

- **`ob-bastion-setup`** (NSS): `configure_nss` no longer silently
  no-ops when `/etc/nsswitch.conf` ships with `passwd:` / `group:`
  commented out or missing. The new `nss_configure_db` helper handles
  three cases (already configured, active line present, missing/
  commented) and refuses to proceed if the resulting line still
  doesn't include `openbastion`. Without this fix, `getent passwd`
  returned nothing for LLNG-managed users and SSH cert auth failed
  with `Invalid user xxx` even though the certificate was valid.

- **`ob-bastion-setup`** (PAM config): `/etc/open-bastion/openbastion.conf`
  is now generated with `authorize_only = true` by default. Without
  this flag, `pam_openbastion`'s `config_validate()` requires both
  `client_id` and `client_secret` for OIDC token introspection —
  which the bastion never receives, since the user authenticates
  with an SSH certificate. Symptom of the old behaviour: PAM
  account step failed with `pam_openbastion: Invalid configuration`
  immediately after a successful certificate authentication.

- **`ob-enroll`**: dropped `curl -f` from `build_curl_opts()` so that
  HTTP 4xx responses surface the portal's actual error body. The
  script already checks `http_code != 200` manually; with `-f` curl
  exited non-zero before the body was read and the user was told
  `Failed to contact portal` regardless of whether the portal was
  unreachable or simply rejecting the request (unknown `client_id`,
  missing scope, Device Authorization Grant disabled, etc.). The
  error messages now include the JSON response and a list of common
  causes.

- **`ob-session-recorder`** (scp / sftp / rsync): the `ForceCommand`
  recorder used to wrap every command in `script` / `asciinema` /
  `ttyrec`, which spawns a PTY. File-transfer protocols exchange a
  binary stream over raw stdio and the PTY's `NL` → `CR+NL`
  translation corrupted it (clients hung or aborted with
  `Connection closed`). The new `is_file_transfer()` detects
  `scp -t/-f`, `sftp-server`, `internal-sftp` and `rsync --server`
  and `exec`s those commands directly via the user's shell. Metadata
  is still written (`format = "transfer"`); only the PTY recording
  is skipped.

- **`ob-session-recorder`** (channel hang): the background session
  timeout (`(sleep N; kill -ALRM $$) &`) inherited stdin/stdout/stderr
  from sshd. sshd waits for every process holding the channel FDs to
  release them before closing the channel, so even after a clean
  `scp` finished the client appeared to hang for up to
  `MAX_SESSION_DURATION` (8 h by default). The subshell now redirects
  its FDs to `/dev/null`, and a `TERM`/`HUP` trap kills the `sleep`
  grandchild on cleanup so we no longer leak an 8-hour sleep per
  session.

### Added

- **`ob-bastion-setup`**: `-c` / `--client-id`, `-S` /
  `--client-secret-file FILE` (use `-` for stdin) and support for the
  `OB_CLIENT_SECRET` environment variable. Secrets passed via file
  or env stay out of `/proc/<pid>/cmdline`. The credentials are
  forwarded to `ob-enroll` via env so they never appear on its
  command line either.

- **`ob-bastion-setup`**: interactive retry on enrollment failure.
  On `invalid_client` or similar, the script asks the user whether
  to provide / update credentials and tries again (up to 3 attempts)
  without restarting the whole setup. Credentials that succeed are
  persisted in `/etc/open-bastion/openbastion.conf` so future
  re-enrollments via `ob-enroll` alone keep working.

- **`ob-bastion-setup`**: interactive prompts for `--server-group`
  and `--client-id` when they are omitted on the CLI. The silent
  `SERVER_GROUP="bastion"` default has been removed. In `--yes`
  (non-interactive) mode both options must now be passed
  explicitly — the script errors out otherwise instead of using
  a default that probably does not match the LLNG configuration.

- **`ob-bastion-setup`** (summary): the post-run banner now reports
  enrollment outcome (`✓ Server enrolled`, `✓ Token installed`,
  `✗ Server enrollment FAILED`) and switches to
  `Bastion Configuration INCOMPLETE` with an `ACTION REQUIRED` block
  when enrollment did not succeed and the user chose to proceed
  anyway.

## [0.2.1] - 2026-05-20

Maintenance release that completes the `llng-pam-module` →
`open-bastion` rebranding in the setup scripts, docs and Docker
demos, and patches a regression in the upstream LemonLDAP::NG
portal image used by the demos. No behavioural change in the PAM
or NSS modules.

### Fixed

- **`ob-bastion-setup` / `ob-backend-setup`**: stop looking for the
  defunct `/usr/sbin/llng-pam-enroll` (renamed to `ob-enroll`); a
  fresh setup no longer prints `[WARN] Server not enrolled. Run
llng-pam-enroll manually after installation.` after a successful
  enrollment.

- **`ob-bastion-setup`**: give /var/lib/open-bastion/sessions mode 3771
  ob-bastion-setup posed mode 1770 (drwxrwx--T) on the sessions
  parent. The ob-session-recorder-wrapper setgid binary creates the
  per-user subdir while it holds effective gid ob-sessions, then
  drops back to the user's gid and execs the recorder script. With
  the parent at 1770 the connecting user (not a member of ob-sessions)
  has no traverse right on the parent, so the script cannot stat
  its own subdir and logs "User sessions directory ... does not
  exist and could not be created", leaving sessions unrecorded.

- Sweep the remaining `llng-*` leftovers across scripts, docs,
  configs and Docker demos so paths, modules, units, packages and
  internal identifiers match the names actually installed by the
  Debian / RPM packages:
  - binaries: `llng-pam-{enroll,heartbeat}`,
    `llng-{ssh-cert,session-recorder,principals}` → `ob-*`
  - modules: `pam_llng.so` → `pam_openbastion.so`,
    `libnss_llng.so` → `libnss_openbastion.so`
  - paths: `/etc/security/pam_llng.*` → `/etc/open-bastion/*`,
    `/var/{cache,log,lib}/pam_llng` → `.../open-bastion`
  - sshd: `/etc/ssh/llng_ca.pub` → `/etc/ssh/open-bastion_ca.pub`,
    dropins → `50-open-bastion-{bastion,backend}.conf`
  - systemd: `pam-llng-heartbeat.timer` → `ob-heartbeat.timer`
  - apt package: `libpam-llng` → `open-bastion`
  - bash/env vars: `PAM_LLNG_*`, `LLNG_RECORDER_*` renamed
    consistently
  - Tests updated to match (`test_ob_session_recorder.sh`,
    `test_integration_maxsec.sh`).
  - Legitimate references to the LemonLDAP::NG SSO portal and to
    the external `llng` CLI client are preserved.

- **CI**: bump GitHub Actions to versions running on Node.js 24
  (#115).

### Upgrade notes

- If you were driving `ob-session-recorder` via the `LLNG_*`
  environment variables (`LLNG_RECORDER_CONFIG`,
  `LLNG_SESSIONS_DIR`, `LLNG_RECORDER_FORMAT`, `LLNG_MAX_SESSION`),
  rename them to their `OB_*` counterparts.

## [0.2.0] - 2026-04-30

This release groups three independent opt-in features (service
accounts, session-containment hardening, syscall-level audit trace)
and a security-analysis update. None of them changes existing
behaviour: a v0.1.5 deployment upgrades to v0.2.0 with no flag set
and runs identically. (Note: v0.1.6 was prepared internally but
never published; its contents are folded into v0.2.0.)

### Added

- **Service accounts (machine accounts)** — local Unix accounts
  declared in `/etc/open-bastion/service-accounts.conf`
  (`0600 root:root`) that LemonLDAP::NG never sees, for CI agents
  and headless tooling.
  - `pam_openbastion` materialises the Unix user on first login
    (`create_user = true`), with forced uid/gid and auto-created
    primary group.
  - `libnss_openbastion` resolves service accounts so `sshd`'s
    pre-auth `getpwnam()` succeeds; path configurable via
    `service_accounts_file =` in `nss_openbastion.conf`.
  - Mode E support via `scripts/ob-service-account-keys`
    (`AuthorizedKeysCommand` helper) so plain (non-SSO-signed) keys
    can authenticate registered service accounts without breaking
    the `AuthorizedKeysFile none` guarantee.
  - New `docker-demo-token-svc/` variant (coexists with
    `docker-demo-token`) and integration tests
    (`tests/test_integration_token_svc.sh` + Phase 7 in
    `tests/test_integration_maxsec.sh`).

- **Session-containment hardening** (`ob-bastion-setup
--enable-hardening`, opt-in, off by default) — closes the known
  SSH evasion channels (`setsid`+`nohup` orphans, deferred
  `at`/`cron` jobs, `systemd-run --user` timers) without any new
  setuid binary.
  - `KillUserProcesses=yes` deployed via
    `/etc/systemd/logind.conf.d/open-bastion.conf` (SIGHUP-applied,
    non-disruptive — does not kill the admin's own session).
  - `/etc/at.allow` empty + `systemctl mask atd` disable `at(1)` for
    non-root users; `/etc/cron.allow` root-only disables `crontab(1)`
    for non-root users (cron itself stays up because Mode E uses
    `/etc/cron.d/open-bastion-krl`).
  - Pre-flight refusal if any non-root user has `Linger=yes`, which
    would let them schedule jobs via `systemd-run --user
--on-active=…` (operator must `loginctl disable-linger <user>`
    before re-running).
  - `nproc` cap (256, `@ob-service` group exempt) as defense in depth
    against fork-bomb-style runaway processes.
  - Templates ship under `/usr/share/open-bastion/hardening/` (read
    only; deployment artefacts in `/etc/` are written by
    `ob-bastion-setup`, not by dpkg/rpm).
  - New `doc/hardening.md` and `tests/test_ob_bastion_setup_hardening.sh`
    (20 tests).

- **Primary audit trace via auditd** (`ob-bastion-setup
--enable-audit-trace`, opt-in, off by default) — syscall-level,
  tamper-evident audit independent of the pty session recording.
  - `/etc/audit/rules.d/open-bastion.rules`: `-S execve -S execveat`
    (both — `execveat` alone bypasses an `execve`-only rule),
    `-S connect`, watches on `/etc/passwd`, `/etc/shadow`,
    `/etc/group`, `/etc/sudoers` (and `.d`), `/etc/ssh/sshd_config`
    (and `.d`), `/var/lib/open-bastion/sessions/`, `/etc/open-bastion/`.
  - `/etc/cron.daily/open-bastion-audit-rotate` — daily SIGUSR1 to
    auditd; combined with `num_logs=7` gives ~1 week local
    retention.
  - `/etc/audit/auditd.conf` is **intentionally not modified** (it
    is a single admin-tunable file owned by the `audit` package; we
    use the drop-in mechanism `rules.d/` and document the
    recommended retention values for the admin to apply manually).
  - Warns and skips (does not refuse) if `auditd` is not installed
    so the rest of `ob-bastion-setup` continues normally.
  - `auditd` is declared as `Recommends:` (Debian) /
    `Recommends:` (RPM) — never installed silently.
  - New `doc/audit.md` and `tests/test_ob_bastion_setup_audit.sh`
    (11 tests).

### Changed

- **Security analysis updated** (`doc/security/02-ssh-connection.md`,
  `doc/security/99-risk-reduce.md`):
  - **R-S18 corrected** — the previous claim that the setgid wrapper
    - sticky bit prevented users from deleting their own recordings
      was inaccurate: the per-user subdirectory is
      `2770 user:ob-sessions`, so the user is owner and can `rm` their
      own files. Score revised from `(P=1, I=1)` to `(P=2, I=1)` —
      syslog `auth.info` (start/end) and the new auditd watch on
      `/var/lib/open-bastion/sessions/` preserve the timeline and
      record any unlink even if the file is deleted. The wrapper still
      provides cross-user isolation (which is what it was always
      really doing).
  - **R-S19 (new)** — session-containment evasion via `setsid`/`nohup`.
    Initial `(P=3, I=3)`; residual `(P=1, I=1)` with hardening +
    audit trace activated.
  - **R-S20 (new)** — deferred action via `at`/`cron`/`systemd-run
--user --on-active=…`. Initial `(P=2, I=3)`; residual `(P=1, I=2)`
    with hardening (limit: pre-existing crontabs in
    `/var/spool/cron/crontabs/` are not purged on activation).
  - **R-S21 (new)** — action not captured by the pty (`execveat`,
    UDP `sendto`, `io_uring`, TIOCSTI, ptrace, intra-session
    `LD_PRELOAD`). Initial `(P=2, I=3)`; residual `(P=1, I=2)` with
    audit trace (limit: UDP `sendto`/`sendmsg` not traced by
    default — opt-in extension documented).
  - New section "Pistes d'amélioration — Containment et Traçabilité"
    in `99-risk-reduce.md` with concrete next-steps (privileged
    session collector, `audisp-syslog` forwarding, MAC profiles,
    cryptographic recording signatures, etc.).

### Security

- `libnss_openbastion`: enforce strict `0600 root:root` on
  `service-accounts.conf` (mirrors `pam_openbastion`).
- Service-account entries are not persisted to the on-disk NSS cache
  to avoid exposing local-only metadata.
- Hardening pre-flight is a **security gate**: the linger check
  fails the step (`return 1`, no `/etc/` writes) even under `--yes`,
  so an operator cannot accidentally bypass it in batch mode.

### Upgrade notes

- All three new features are **opt-in**:
  - Service accounts: leave `service_accounts_file` unset in
    `openbastion.conf` / `nss_openbastion.conf`.
  - Hardening: do not pass `--enable-hardening` to `ob-bastion-setup`.
  - Audit trace: do not pass `--enable-audit-trace`.

  A v0.1.5 deployment upgraded to v0.2.0 with no flag set behaves
  exactly like v0.1.5.

- On a dedicated bastion host, the recommended invocation is now
  `ob-bastion-setup --portal … --enable-hardening --enable-audit-trace`.
  Both flags can be combined with `--max-security` (Mode E).

- The hardening step refuses to run if any non-root user has
  `Linger=yes`. If you have legitimate lingering services, disable
  linger (`loginctl disable-linger <user>`) before re-running, or
  leave `--enable-hardening` off.

- `auditd` is a `Recommends:` not `Depends:` — it is **not**
  pulled in automatically by `apt install --no-install-recommends`.
  Operators who want the audit trace must `apt install auditd`
  explicitly.

- `v0.1.6` was prepared internally (CHANGELOG entry + commit
  `c591109`) but **never tagged or published**. Its contents are
  folded into v0.2.0; no v0.1.6 → v0.2.0 upgrade path exists.

## [0.1.5] - 2026-04-20

### Security

- **SSH key fingerprint binding on `/pam/authorize` and `/pam/verify`**
  (requires LemonLDAP::NG **PamAccess ≥ 0.1.16** and **SSHCA ≥ 0.1.16**).
  `pam_openbastion` now forwards the SHA256 fingerprint of the SSH key
  used to open the session in the JSON body of both endpoints. LLNG
  cross-checks it against the user's persistent session (`_sshCerts`)
  and rejects the call if the certificate is unknown, revoked, or
  expired — independently of the local `sshd` KRL. This closes a gap
  where a certificate revoked on the portal could still open a session
  (or escalate via sudo) until the KRL propagated, or at all if
  `RevokedKeys` was missing from `sshd_config`.
- **Out-of-band fingerprint channel** for modern OpenSSH (≥ 9.x), which
  does not propagate `SSH_USER_AUTH` to the PAM environment during
  `pam_acct_mgmt`:
  - New helper `/usr/local/sbin/ob-ssh-principals`, wired as
    `AuthorizedPrincipalsCommand %u %f` by `ob-bastion-setup` and
    `ob-backend-setup`. It drops the fingerprint to
    `/run/open-bastion/ssh-fp/<sshd-session-pid>.fp` atomically
    (`mktemp` + `mv`).
  - `pam_openbastion` walks `/proc` up to the `sshd-session` ancestor
    and reads the matching file, with strict validation: directory not
    group/world-writable, file regular, owner == spool directory owner,
    mode `0600`, `nlink == 1`, content matches `SHA256:<base64>`, size
    ≤ 512 B. Fall back to parsing `SSH_USER_AUTH` if a custom-patched
    sshd does expose it.
  - Spool directory deployed as `0700 nobody:nogroup` (the
    `AuthorizedPrincipalsCommandUser`); hardened `systemd-tmpfiles`
    drop-in (`/etc/tmpfiles.d/open-bastion-ssh-fp.conf`) recreates it
    at boot so `/run` wipes do not silently disable the binding.
- **Strict SHA256 filter.** `pam_openbastion` refuses to forward a
  fingerprint that is not in the `SHA256:<base64>` form expected by
  LLNG (so an `sshd` configured with `FingerprintHash md5` cannot
  trigger systematic HTTP 400 from the portal). Non-SHA256 values are
  discarded and the call falls back to the pre-binding behaviour.

### Added

- `ob_client`: new top-level `fingerprint` field in `/pam/authorize`
  and `/pam/verify` request bodies when available. `ob_verify_token()`
  grows an optional `fingerprint` parameter.
- `ob_ssh_cert_info_t`: new `key_fingerprint` field populated from the
  spool or, as a fallback, from `SSH_USER_AUTH`.
- Integration tests (`tests/test_integration_{docker,maxsec}.sh`):
  three new cases — fingerprint accepted/unknown/malformed on
  `/pam/authorize`, rejection of a certificate revoked via
  `/ssh/myrevoke` without KRL refresh, and an end-to-end SSH attempt
  with that revoked certificate that must be refused at the PAM
  `account` phase.

### Upgrade notes

- Re-run `ob-bastion-setup` or `ob-backend-setup` on every bastion /
  backend: they now install `/usr/local/sbin/ob-ssh-principals`, the
  `/run/open-bastion/ssh-fp` spool, and the `systemd-tmpfiles`
  drop-in. The `AuthorizedPrincipalsCommand` line in
  `sshd_config.d/50-llng-bastion.conf` is updated to pass `%u %f`.
- Bastions running against a LemonLDAP::NG portal without PamAccess
  0.1.16 remain fully functional: the portal ignores the `fingerprint`
  field (backward-compatible). The extra security layer activates as
  soon as the portal is upgraded.
- `ExposeAuthInfo yes` is **no longer required** for the fingerprint
  binding (the helper + spool are self-sufficient); it remains useful
  for session auditing.

## [0.1.4] - 2026-04-18

### Security

- **Session recorder wrapper** (`ob-session-recorder-wrapper`): full rewrite
  with defense-in-depth against privilege escalation
  - Explicitly drop elevated gid via `setregid()` before `exec` (fixes a
    vector where the `ob-sessions` gid would leak into the recorder
    script's saved gid and child processes)
  - Switch to directory-based privilege separation: the wrapper creates
    `$SESSIONS_DIR/$USER` with mode `2770` (setgid) so files inside
    inherit the `ob-sessions` group without the script needing elevated
    gid
  - Sanitize environment before `exec`: strip `LD_PRELOAD`,
    `LD_LIBRARY_PATH`, `LD_AUDIT`, `BASH_ENV`, `ENV`, `SHELLOPTS`,
    `BASHOPTS`, `CDPATH`, `GCONV_PATH`, `HOSTALIASES`, `LOCALDOMAIN`,
    `LOCPATH`, `MALLOC_TRACE`, `NIS_PATH`, `NLSPATH`, `RESOLV_HOST_CONF`,
    `RES_OPTIONS`, `TMPDIR`; force `PATH=/usr/sbin:/usr/bin:/sbin:/bin`
  - Validate username against `^[a-z_][a-z0-9_.-]*$` before use in
    path construction (prevents path traversal)
  - Resolve username from the real uid via `getpwuid()` instead of a
    user-controllable env variable
  - Fix TOCTOU races in session directory creation by using
    `fstat`/`fchown`/`fchmod` on an opened fd (CodeQL)
- **`scripts/ob-session-recorder`**: derive `SESSION_USER` from `id -un`
  instead of `$USER`; validate with the same regex
- **NSS module** (`libnss_openbastion`):
  - Config file and token file now opened with `O_NOFOLLOW` and verified
    via `fstat`: must be owned by root, must be a regular file, must
    not be group/world-writable; token file must not be
    group/world-readable
  - Add integer overflow check and 256 KB response cap in
    `write_callback`
  - Emit syslog diagnostics for every previously-silent rejection path
- **Defense-in-depth sudo**:
  - New system group `open-bastion-sudo` created automatically by
    `debian/postinst` and the RPM pre-install scriptlet
  - `pam_openbastion` session hook syncs membership on every login:
    `sudo_allowed=true` → add user to the group, `false` → remove
  - `nscd` group cache invalidated after a membership change so `sudo`
    sees the update immediately
  - `ob-bastion-setup` writes `/etc/sudoers.d/open-bastion` as
    `%open-bastion-sudo ALL=(ALL) ALL` for new installs (does not
    overwrite an existing file)

### Fixed

- **NSS configuration path**: `libnss_openbastion` now reads its config
  from `/etc/open-bastion/nss_openbastion.conf` — where CMake installs
  it and where `ob-bastion-setup`/`ob-backend-setup` have always
  written. The module was hard-coded to `/etc/nss_llng.conf` (leftover
  from the `llng-pam-module` → `open-bastion` rename), so NSS never
  found its config and silently refused to resolve users. Docker demos
  masked this with a `useradd -m` fallback that created local accounts
  whenever NSS failed; the fallback is removed and demos now fail fast
  on real NSS breakage
- `ob-bastion-setup` / `ob-backend-setup`: update internal variable and
  write config to the new NSS path

### Added

- **`quick-start/`** directory: minimal 2-container demo (LLNG portal +
  single SSH server) using `yadd/lemonldap-ng-portal` directly,
  relying on the plugin autoloader (no `customPlugins` edit needed).
  README documents installing the four Open-Bastion plugins
  (`pam-access`, `ssh-ca`, `oidc-device-authorization`,
  `oidc-device-organization`) on an existing LemonLDAP::NG via
  `lemonldap-ng-store` or Debian packages
- `docker-demo-cert/README.md`: hands-on enrollment walkthrough fully
  refreshed (container names, config paths, script names) after the
  `llng-*` → `open-bastion`/`ob-*` rename

### Upgrade notes

- **NSS config path**: if you deployed v0.1.3 and ran
  `ob-bastion-setup` or `ob-backend-setup`, you have an orphaned
  `/etc/nss_llng.conf`. Re-running the setup script after upgrade
  writes the config to the new path and fixes user resolution. You can
  then `rm /etc/nss_llng.conf` to clean up. The Debian/RPM postinst
  does not migrate it automatically.
- **Session recorder usernames**: usernames with characters outside
  `[a-z_][a-z0-9_.-]*` (e.g. AD-style `DOMAIN\user` or `user@realm`)
  are now rejected by the wrapper. Open-Bastion's NSS module generates
  POSIX-safe usernames, so this only affects custom integrations.
- **NSS token file permissions**: the module now requires
  `/etc/open-bastion/token` to be mode `0600 root:root`. `ob-enroll`
  writes it with these permissions by default; custom deployments using
  `0640` with a group read will need to tighten.

## [0.1.3] - 2026-04-16

### Security

- **Session recording privilege separation** via setgid wrapper
  (`ob-session-recorder-wrapper`, group `ob-sessions`, directory mode
  `1770`)
- New risk R-S18: session recording tampering (mitigated P=1/I=1)

### Fixed

- PAM module name: `pam_llng.so` → `pam_openbastion.so` across scripts
  and setup tooling
- NSS module symbols: `_nss_llng_*` → `_nss_openbastion_*`
- NSS `nsswitch.conf` source name uses `openbastion`; `server_token_file`
  config key aligned
- `ob-enroll`: send `client_secret` to the device endpoint (optional but
  accepted by RFC 8628)
- `ob-bastion-setup`: add `Include` directive, `AuthorizedPrincipalsCommand`,
  `PermitRootLogin no`, NSS configuration, `pam_mkhomedir.so`
- Session recorder paths: `ob-session-recorder`, `/etc/open-bastion/`
- Sudo Mode E: remove `pam_unix.so` from `account` stack (NSS-only
  users), create `/etc/sudoers.d/open-bastion`

### Added

- Pre-hardening bootstrap: `securetty ttyS0`, `PermitRootLogin no`,
  emergency-access service account

## [0.1.2] - 2026-04-13

### Added

- **Mode E: Maximum Security** (#100): New security configuration enforcing the
  strictest SSH posture
  - SSH authentication via SSO-signed certificates only (`AuthorizedKeysFile none`)
  - sudo only via fresh LLNG temporary token (PAM-access re-authentication)
  - Mandatory KRL (Key Revocation List) with automatic refresh via `/ssh/revoked`
  - `--max-security` option in `ob-backend-setup` and `ob-bastion-setup` scripts
  - KRL refresh script with proper SSL/timeout option inheritance
- **docker-demo-maxsec**: Full Docker Compose demo for Mode E architecture
- **CI integration tests for Mode E** (`test_integration_maxsec.sh`): Validates
  certificate-only auth, unsigned key rejection, KRL configuration, sudo PAM
  hardening, and password authentication is disabled
- **EBIOS security study refactored** for maximum security target:
  - `doc/security/00-architecture.md` translated to French with Mode E introduction
  - `doc/security/02-ssh-connection.md` simplified to single architecture (Mode E)
  - `doc/security/03-offboarding.md` simplified to Mode E offboarding procedure
  - New risks R-S15 (stale KRL) and R-S16 (sudo escalation) documented

### Fixed

- **`OB_BASTION_JWT` → `LLNG_BASTION_JWT`**: Aligned environment variable name
  across all files to match the actual PAM module code and `ob-ssh-proxy`
- **`AllowAgentForwarding no`** on bastion: Agent forwarding is not needed
  (ob-ssh-proxy handles JWT injection, not ProxyJump)
- **ProxyJump references replaced with `ob-ssh-proxy`** in security documentation:
  native ProxyJump is incompatible with bastion JWT injection
- **KRL format validation**: Verify SSH KRL magic bytes (`SSHKRL`) before replacing
  the revocation file, preventing HTML error pages from breaking sshd

## [0.1.1] - 2026-02-07

### Added

- **Supplementary groups synchronization** (#95): LLNG can now manage Unix supplementary
  groups on target servers via the `managed_groups` configuration
  - **Local whitelist for managed groups** (`allowed_managed_groups`): Defense-in-depth
    option to restrict which groups LLNG can modify on each server
- **CrowdSec IP/CIDR whitelist** (#96): New `crowdsec_whitelist` option to bypass
  CrowdSec checks for trusted IPs/networks (VPN exit nodes, corporate NAT)
  - Supports IPv4, IPv6, and CIDR notation
  - Prevents self-inflicted DoS on shared IPs

### Fixed

- **TOCTOU race condition in cache_key.c** (#97): Use `open()` with
  `O_CREAT|O_EXCL|O_NOFOLLOW` instead of `fopen()` to prevent symlink attacks
- Check `fclose()` return value to detect flush errors before rename

## [0.1.0] - 2025-02-07

Initial release.
