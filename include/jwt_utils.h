/*
 * jwt_utils.h - JWT generation utilities for OAuth2 client authentication
 *
 * Copyright (C) 2025 Linagora
 * License: AGPL-3.0
 */

#ifndef JWT_UTILS_H
#define JWT_UTILS_H

/*
 * Generate client_secret_jwt assertion (RFC 7523)
 *
 * Creates a JWT signed with HMAC-SHA256 for client authentication
 * to OAuth2 token and introspection endpoints.
 *
 * JWT claims:
 *   - iss: client_id
 *   - sub: client_id
 *   - aud: audience (endpoint URL)
 *   - exp: now + 300 seconds
 *   - iat: now
 *   - jti: unique UUID v4
 *
 * @param client_id     OIDC client identifier
 * @param client_secret OIDC client secret (used as HMAC-SHA256 key)
 * @param audience      OAuth2 endpoint URL (token, introspection, etc.; becomes "aud" claim)
 * @return Dynamically allocated JWT string or NULL on error
 *         Caller must free the result with free()
 */
char *generate_client_jwt(const char *client_id,
                          const char *client_secret,
                          const char *audience);

#endif /* JWT_UTILS_H */
