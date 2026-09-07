# LemonLDAP::NG SSO with pre-initialized server tokens
#
# This extends the standard LLNG portal image to pre-create
# server tokens at startup for bastion and backend.

# Pinned, not :latest, on purpose.
#
# ob-bastion-id asks POST /pam/whoami and falls back to the legacy
# /pam/bastion-token probe on portals that predate it. This demo is the only
# thing in the tree that exercises that fallback, and it does so only because
# the portal it runs happens to be old. The day :latest ships the 0.6.0
# plugins, the fallback would lose its coverage silently -- the suite would
# stay green while testing the other path.
#
# 2.23.3-3 is a portal generation without /pam/whoami, without request-signature
# verification and without pamAccessRequireFingerprint, which is exactly the
# shape the fallback exists for. Point another demo at :latest to cover the new
# generation when an image carrying it is published; this one stays here.
ARG PORTAL_IMAGE=yadd/lemonldap-ng-portal:2.23.3-3-non-root
FROM ${PORTAL_IMAGE}

# Create SSH directory for SSHCA plugin (must be done as root during build)
USER root
RUN mkdir -p /var/lib/lemonldap-ng/ssh && chown www-data:www-data /var/lib/lemonldap-ng/ssh

# Upstream image ships both /etc/nginx/uwsgi_params and portal-nginx.conf with
# `uwsgi_param HTTP_HOST $host;`. uwsgi concatenates duplicate params, so
# LLNG sees vhost "localhost, localhost" and rejects all requests.
RUN sed -i '/uwsgi_param HTTP_HOST/d' /etc/lemonldap-ng/portal-nginx.conf
USER www-data

# Copy token initialization script to run during container init
COPY --chmod=755 init-tokens.sh /etc/cont-init.d/10-init-tokens

# Keep original entrypoint and command
