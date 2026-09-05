# Configuration Reference

## Boolean values

Boolean settings accept exactly `true`, `yes`, `1`, `on` and `false`, `no`,
`0`, `off` — lowercase only. Any other value (an empty value, `TRUE`, `tru`,
`enabled`, …) is a **fatal configuration error**: the offending key and value
are logged to syslog and the PAM module refuses to start rather than guessing.

This is deliberate. Before, an unrecognised value silently meant `false`, so a
typo in `verify_ssl` disabled TLS certificate verification without any warning.

The same strict rule applies to PAM module arguments in `/etc/pam.d/*`, where
both `ssh_cert_aware=true` and `ssh_cert_aware="true"` are accepted.

## Comments

A `#` or `;` at the start of a line comments out the whole line. A `#` may also
appear at the end of a value line:

```ini
verify_ssl = true          # comment: everything from '#' is ignored
```

The rule for inline comments is narrow on purpose, so it can never truncate a
legitimate value:

| Written | Value used | Why |
|---|---|---|
| `verify_ssl = true # prod` | `true` | `#` preceded by whitespace ⇒ comment |
| `portal_url = https://sso.example.com/#frag` | `https://sso.example.com/#frag` | `#` not preceded by whitespace |
| `client_secret = s3cr3t # keep` | `s3cr3t # keep` | secret-bearing key, never stripped |
| `server_group = "prod # 2"` | `prod # 2` | quoted value, never stripped |
| `server_group = "prod" # note` | `prod` | value ends at the closing quote |

Keys exempt from inline-comment stripping (their value is an opaque secret or
hash, where `#` is an ordinary character): `client_secret`, `notify_secret`,
`webhook_secret`, `request_signing_secret`, `crowdsec_bouncer_key`,
`crowdsec_password`, `cert_pin`.

For any other key, put the value in double quotes if it must contain a `#`
preceded by a space.

## Main Configuration File

### /etc/open-bastion/openbastion.conf

```ini
# Required: LemonLDAP::NG portal URL
portal_url = https://auth.example.com

# Required: OIDC client credentials
client_id = pam-access
client_secret = your-secret

# Server token file (created and refreshed by ob-heartbeat)
# The token lives under /var/lib/open-bastion/ (runtime state, per the FHS)
# rather than /etc; it is refreshed automatically by ob-heartbeat.
server_token_file = /var/lib/open-bastion/token

# Server group for authorization rules
server_group = default

# HTTP settings
timeout = 10
verify_ssl = true
# ca_cert = /etc/ssl/certs/custom-ca.pem

# Cache settings
cache_enabled = true
cache_dir = /var/cache/open-bastion
cache_ttl = 300
cache_ttl_high_risk = 60
high_risk_services = sudo,su

# Logging: error, warn, info, debug
log_level = warn

# Audit logging
audit_enabled = true
audit_log_file = /var/log/open-bastion/audit.json
audit_to_syslog = true
audit_level = 1  # 0=critical, 1=auth events, 2=all

# Rate limiting
rate_limit_enabled = true
rate_limit_max_attempts = 5
rate_limit_initial_lockout = 30
rate_limit_max_lockout = 3600

# Group synchronization (#38)
# Local whitelist of groups allowed to be managed (optional, defense-in-depth)
# If configured, only groups in this list AND in LLNG's managed_groups will be synced
# allowed_managed_groups = docker,developers,readonly

# Webhook notifications (optional)
# notify_enabled = true
# notify_url = https://alerts.example.com/webhook
# notify_secret = your-hmac-secret
```

For detailed documentation on specific features:

- [Cache Brute-Force Protection](security.md#cache-brute-force-protection)
- [Rate Limiting](security.md#rate-limiting)

## PAM Module Arguments

Arguments can be passed directly in PAM configuration:

```
auth required pam_openbastion.so portal_url=https://auth.example.com debug
```

| Argument             | Description                            |
| -------------------- | -------------------------------------- |
| `conf=/path/to/file` | Use alternate config file              |
| `portal_url=URL`     | Override portal URL                    |
| `server_group=GROUP` | Override server group                  |
| `debug`              | Enable debug logging                   |
| `authorize_only`     | Skip password check (for SSH key mode) |
| `no_cache`           | Disable token caching                  |
| `insecure`           | Skip SSL verification                  |
| `no_audit`           | Disable audit logging                  |
| `no_rate_limit`      | Disable rate limiting                  |
| `no_bind_ip`         | Disable IP binding for tokens          |

## Server Enrollment Script

The `ob-enroll` script automates the Device Authorization Grant flow.

### Usage

```bash
sudo ob-enroll [OPTIONS]
```

### Options

| Option                       | Description                                                      |
| ---------------------------- | ---------------------------------------------------------------- |
| `-p, --portal URL`           | LemonLDAP::NG portal URL                                         |
| `-c, --client-id ID`         | OIDC client ID (default: pam-access)                             |
| `-s, --client-secret SECRET` | OIDC client secret                                               |
| `-g, --server-group GROUP`   | Server group name (default: default)                             |
| `-t, --token-file FILE`      | Where to save the token (default: /var/lib/open-bastion/token)   |
| `-C, --config FILE`          | Configuration file (default: /etc/open-bastion/openbastion.conf) |
| `-k, --insecure`             | Skip SSL certificate verification                                |
| `-q, --quiet`                | Quiet mode                                                       |
| `-h, --help`                 | Show help                                                        |

### Examples

```bash
# Enroll using settings from config file
sudo ob-enroll

# Enroll with explicit parameters
sudo ob-enroll -p https://auth.example.com -s mysecret

# Enroll for a specific server group
sudo ob-enroll -g production

# Enroll with custom token file location
sudo ob-enroll -t /var/lib/open-bastion/server.token
```

### Manual Enrollment (Without Script)

If you prefer manual enrollment:

#### 1. Initiate enrollment

```bash
curl -X POST https://auth.example.com/oauth2/device \
  -d "client_id=pam-access" \
  -d "scope=pam:server"
```

Response:

```json
{
  "device_code": "...",
  "user_code": "ABCD-EFGH",
  "verification_uri": "https://auth.example.com/device",
  "expires_in": 1800
}
```

#### 2. Admin approval

An administrator visits `https://auth.example.com/device`, logs in, and enters the user code.

#### 3. Get access token

```bash
curl -X POST https://auth.example.com/oauth2/token \
  -d "grant_type=urn:ietf:params:oauth:grant-type:device_code" \
  -d "device_code=<device_code_from_step_1>" \
  -d "client_id=pam-access" \
  -d "client_secret=your-secret"
```

#### 4. Save the token

```bash
echo "<access_token>" | sudo tee /var/lib/open-bastion/token
sudo chmod 600 /var/lib/open-bastion/token
```

## See Also

- [LemonLDAP::NG Configuration](llng-configuration.md) - Server-side LLNG setup
- [PAM Authentication Modes](pam-modes.md) - PAM configurations
- [Service Accounts](service-accounts.md) - Service account configuration
- [CrowdSec Integration](crowdsec.md) - CrowdSec configuration
- [Security Features](security.md) - Security options
