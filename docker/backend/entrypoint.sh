#!/bin/bash
# LLNG Backend Entrypoint
# Downloads CA key from SSO and configures sshd with user creation

set -e

PORTAL_URL="${LLNG_PORTAL_URL:-http://sso}"
SERVER_GROUP="${LLNG_SERVER_GROUP:-backend}"
CLIENT_ID="${LLNG_CLIENT_ID:-pam-access}"
CLIENT_SECRET="${LLNG_CLIENT_SECRET:-pamsecret}"
SERVER_TOKEN="${LLNG_SERVER_TOKEN:-}"
SSH_CA_FILE="/etc/ssh/llng_ca.pub"
TOKEN_FILE="/etc/security/llng_server_token"

echo "=== LLNG Backend Starting ==="
echo "Portal URL: $PORTAL_URL"
echo "Server Group: $SERVER_GROUP"

# Wait for SSO to be available
echo "Waiting for SSO..."
for i in {1..60}; do
    if curl -sf "$PORTAL_URL/" >/dev/null 2>&1; then
        echo "SSO is available"
        break
    fi
    sleep 1
done

# Download SSH CA public key
echo "Downloading SSH CA public key..."
for i in {1..10}; do
    if curl -sf "$PORTAL_URL/ssh/ca" -o "$SSH_CA_FILE" 2>/dev/null; then
        echo "CA key saved to $SSH_CA_FILE"
        cat "$SSH_CA_FILE"
        break
    fi
    echo "Retry $i..."
    sleep 2
done

if [ ! -f "$SSH_CA_FILE" ]; then
    echo "WARNING: Could not download CA key, SSH cert auth may not work"
fi

# Configure sshd for certificate authentication
cat > /etc/ssh/sshd_config.d/llng-backend.conf << EOF
# LemonLDAP::NG Backend Configuration

# Trust LLNG SSH CA
TrustedUserCAKeys $SSH_CA_FILE

# Enable certificate authentication
PubkeyAuthentication yes

# Disable password authentication
PasswordAuthentication no
KbdInteractiveAuthentication no

# No agent forwarding on backend
AllowAgentForwarding no

# Use PAM for authorization and user creation
UsePAM yes

# Security settings
X11Forwarding no
PermitRootLogin no
EOF

# Create server token file if token provided
if [ -n "$SERVER_TOKEN" ]; then
    echo "$SERVER_TOKEN" > "$TOKEN_FILE"
    chmod 600 "$TOKEN_FILE"
    echo "Server token configured"
else
    echo "WARNING: No LLNG_SERVER_TOKEN provided, PAM authorization will fail"
fi

# Create PAM LLNG configuration
cat > /etc/security/pam_llng.conf << EOF
# LemonLDAP::NG PAM configuration for Backend

portal_url = $PORTAL_URL
server_group = $SERVER_GROUP

# Client credentials
client_id = $CLIENT_ID
client_secret = $CLIENT_SECRET

# Server token for authorization
server_token_file = $TOKEN_FILE

# HTTP settings
timeout = 10
verify_ssl = false

# Cache settings
cache_enabled = true
cache_dir = /var/cache/pam_llng
cache_ttl = 300

# User creation
create_user = true
create_home = true
default_shell = /bin/bash

# Logging
log_level = info
EOF

chmod 600 /etc/security/pam_llng.conf

# Create NSS LLNG configuration
cat > /etc/nss_llng.conf << EOF
# LemonLDAP::NG NSS configuration

portal_url = $PORTAL_URL
server_token_file = $TOKEN_FILE

# Cache settings
cache_ttl = 300

# UID/GID range for dynamic users
min_uid = 10000
max_uid = 60000
default_gid = 100

# Defaults
default_shell = /bin/bash
default_home_base = /home
EOF

chmod 644 /etc/nss_llng.conf

# Configure NSS to use LLNG for user/group resolution
sed -i 's/^passwd:.*/passwd:         files llng/' /etc/nsswitch.conf
sed -i 's/^group:.*/group:          files llng/' /etc/nsswitch.conf
echo "NSS configured to use LLNG"

# Configure PAM to create home directories on first login
cat > /etc/pam.d/sshd << EOF
# PAM configuration for SSH with LemonLDAP::NG
auth       required     pam_permit.so
account    required     pam_llng.so
session    required     pam_unix.so
session    optional     pam_mkhomedir.so skel=/etc/skel umask=0022
EOF

# Ensure sshd_config.d is included
if ! grep -q "Include /etc/ssh/sshd_config.d" /etc/ssh/sshd_config; then
    echo "Include /etc/ssh/sshd_config.d/*.conf" >> /etc/ssh/sshd_config
fi

# NSS module now resolves users dynamically from LLNG
# Test that NSS is working
echo "Testing NSS module..."
if getent passwd dwho >/dev/null 2>&1; then
    echo "  NSS module working: $(getent passwd dwho)"
else
    echo "  WARNING: NSS module not working, falling back to static users"
    for user in dwho rtyler; do
        if ! getent passwd "$user" >/dev/null 2>&1; then
            useradd -m -s /bin/bash "$user" 2>/dev/null && echo "  Created user: $user"
        fi
    done
fi

echo "=== Backend Configuration Complete ==="
echo "SSH listening on port 22"
echo "Users can connect with SSH certificates from LLNG"
echo "Sudo available for authorized users (rtyler)"

# Execute the command (sshd)
exec "$@"
