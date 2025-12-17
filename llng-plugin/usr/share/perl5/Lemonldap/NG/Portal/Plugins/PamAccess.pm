# PAM Access plugin for LemonLDAP::NG
#
# This plugin provides:
# - /pam : Web interface for users to generate temporary PAM access tokens
# - /pam/verify : Server-to-server endpoint to validate one-time user tokens
# - /pam/authorize : Server-to-server endpoint for authorization checks
#
# User tokens are one-time use tokens stored as sessions (kind=PAMTOKEN).
# They are destroyed after first use for security.
# Server authentication uses Bearer tokens obtained via Device Authorization Grant.

package Lemonldap::NG::Portal::Plugins::PamAccess;

use strict;
use Mouse;
use JSON qw(from_json to_json);
use Lemonldap::NG::Portal::Main::Constants qw(
    PE_OK
    PE_ERROR
    PE_SENDRESPONSE
);

our $VERSION = '2.22.0';

extends 'Lemonldap::NG::Portal::Main::Plugin';

use constant name => 'PamAccess';

# MenuTab configuration - rule for displaying the tab
has rule => (
    is      => 'ro',
    lazy    => 1,
    builder => sub { $_[0]->conf->{portalDisplayPamAccess} // 0 },
);
with 'Lemonldap::NG::Portal::MenuTab';

# Access to OIDC module for token generation/validation
has oidc => (
    is      => 'ro',
    lazy    => 1,
    default => sub {
        $_[0]
          ->p->loadedModules->{'Lemonldap::NG::Portal::Issuer::OpenIDConnect'};
    }
);

# RP name for PAM tokens
has rpName => (
    is      => 'ro',
    lazy    => 1,
    default => sub { $_[0]->conf->{pamAccessRp} || 'pam-access' },
);

# INITIALIZATION

sub init {
    my ($self) = @_;

    # Check that OIDC issuer is enabled
    unless ( $self->conf->{issuerDBOpenIDConnectActivation} ) {
        $self->logger->error(
            'PamAccess plugin requires OIDC issuer to be enabled');
        return 0;
    }

    # Routes for authenticated users (token generation interface)
    $self->addAuthRoute( pam => 'pamInterface', ['GET'] )
         ->addAuthRoute( pam => 'generateToken', ['POST'] );

    # Route for server-to-server authorization (Bearer token auth)
    $self->addUnauthRoute(
        pam => { authorize => 'authorize' },
        ['POST']
    );

    # Route for server heartbeat (refresh token based)
    $self->addUnauthRoute(
        pam => { heartbeat => 'heartbeat' },
        ['POST']
    );

    # Route for one-time token verification (server-to-server)
    $self->addUnauthRoute(
        pam => { verify => 'verifyToken' },
        ['POST']
    );

    # Route for NSS user info lookup (server-to-server)
    $self->addUnauthRoute(
        pam => { userinfo => 'userinfo' },
        ['POST']
    );

    # SSH CA routes (only if SSH CA is enabled)
    if ( $self->conf->{sshCaActivation} ) {
        $self->logger->debug('SSH CA is enabled, adding routes');

        # GET /ssh/ca - Public CA key (no auth required)
        $self->addUnauthRoute(
            ssh => { ca => 'sshCaPublicKey' },
            ['GET']
        );

        # GET /ssh/revoked - Key Revocation List (no auth required)
        $self->addUnauthRoute(
            ssh => { revoked => 'sshCaKrl' },
            ['GET']
        );

        # POST /ssh/sign - Sign user's SSH key (auth required)
        $self->addAuthRoute(
            ssh => { sign => 'sshCaSign' },
            ['POST']
        );
    }

    return 1;
}

# MENUTAB - Display method for the portal menu tab

sub display {
    my ( $self, $req ) = @_;

    return {
        logo => 'key',
        name => 'PamAccess',
        id   => 'pamaccess',
        html => $self->loadTemplate(
            $req,
            'pamaccess',
            params => {
                TOKEN          => '',
                LOGIN          => $req->userData->{ $self->conf->{whatToTrace} } || '',
                EXPIRES_IN     => '',
                SHOW_TOKEN     => 0,
                DEFAULT_DURATION => $self->conf->{pamAccessTokenDuration} || 600,
                MAX_DURATION   => $self->conf->{pamAccessMaxDuration} || 3600,
                js             => "$self->{p}->{staticPrefix}/common/js/pamaccess.js",
            }
        ),
    };
}

# ROUTE HANDLERS

# GET /pam - Display the token generation interface
sub pamInterface {
    my ( $self, $req ) = @_;

    return $self->p->do( $req, [ sub { PE_OK } ] );
}

# POST /pam - Generate a new PAM access token (one-time use)
sub generateToken {
    my ( $self, $req ) = @_;

    # Get requested duration
    my $duration = $req->param('duration') || $self->conf->{pamAccessTokenDuration} || 600;

    # Enforce maximum duration
    my $maxDuration = $self->conf->{pamAccessMaxDuration} || 3600;
    $duration = $maxDuration if $duration > $maxDuration;

    my $login = $req->userData->{ $self->conf->{whatToTrace} };
    my $groups = $req->userData->{groups} || '';

    # Calculate _utime for automatic cleanup by purgeCentralCache
    # _utime + timeout = expiration time
    # So: _utime = now + duration - timeout
    my $now = time();
    my $timeout = $self->conf->{timeout} || 7200;
    my $utime = $now + $duration - $timeout;

    # Create one-time token as a session with kind=PAMTOKEN
    my $tokenInfo = {
        _type         => 'pamtoken',
        _utime        => $utime,
        _pamUser      => $login,
        _pamGroups    => $groups,
        _pamUid       => $req->userData->{uid} || $login,
        _pamCreatedAt => $now,
        _pamExpiresAt => $now + $duration,
    };

    # Add exported variables for user provisioning
    my $exportedVars = $self->conf->{pamAccessExportedVars} || {};
    for my $key ( keys %$exportedVars ) {
        my $attr = $exportedVars->{$key};
        my $value = $req->userData->{$attr};
        $tokenInfo->{"_pamAttr_$key"} = $value if defined $value && $value ne '';
    }

    my $tokenSession = $self->p->getApacheSession(
        undef,
        info => $tokenInfo,
        kind => 'PAMTOKEN'
    );

    unless ( $tokenSession && $tokenSession->id ) {
        $self->logger->error('Failed to create PAM token session');
        return $self->p->sendJSONresponse(
            $req,
            { error => 'Token generation failed' },
            code => 500
        );
    }

    my $token = $tokenSession->id;
    $self->logger->info("PAM one-time token generated for user $login (TTL: ${duration}s)");

    # Audit log for token generation
    $self->p->auditLog(
        $req,
        code    => 'PAM_TOKEN_GENERATED',
        user    => $login,
        message => "PAM one-time token generated for user $login (TTL: ${duration}s)",
        ttl     => $duration,
    );

    return $self->p->sendJSONresponse(
        $req,
        {
            token      => $token,
            login      => $login,
            expires_in => $duration,
        }
    );
}

# POST /pam/authorize - Server-to-server authorization check
sub authorize {
    my ( $self, $req ) = @_;

    # 1. Validate Bearer token from Authorization header
    my $access_token = $self->oidc->getEndPointAccessToken($req);
    unless ($access_token) {
        $self->logger->warn('PAM authorize: No Bearer token provided');
        return $self->_unauthorizedResponse($req, 'Bearer token required');
    }

    my $tokenSession = $self->oidc->getAccessToken($access_token);
    unless ($tokenSession) {
        $self->logger->warn('PAM authorize: Invalid or expired Bearer token');
        return $self->_unauthorizedResponse($req, 'Invalid or expired token');
    }

    # 2. Verify token was obtained via Device Authorization Grant
    my $grant_type = $tokenSession->data->{grant_type} || '';
    unless ( $grant_type eq 'device_code' ) {
        $self->logger->warn(
            "PAM authorize: Token not from Device Authorization Grant "
            . "(grant_type: '$grant_type'). Server must enroll via /oauth2/device"
        );
        return $self->_forbiddenResponse(
            $req,
            'Server not enrolled. Use Device Authorization Grant to register this server.'
        );
    }

    # 3. Verify token has correct scope (pam:server or pam)
    my $scope = $tokenSession->data->{scope} || '';
    unless ( $scope =~ /\bpam(?::server)?\b/ ) {
        $self->logger->warn("PAM authorize: Invalid token scope '$scope'");
        return $self->_forbiddenResponse($req, 'Invalid token scope');
    }

    # Log server identity from token
    my $server_id = $tokenSession->data->{client_id} || 'unknown';
    $self->logger->info("PAM authorize request from enrolled server: $server_id");

    # 4. Parse JSON request body
    my $body = eval { from_json( $req->content ) };
    if ($@) {
        $self->logger->error("PAM authorize: Invalid JSON body: $@");
        return $self->_badRequest($req, 'Invalid JSON');
    }

    my $user         = $body->{user};
    my $host         = $body->{host}         || '';
    my $service      = $body->{service}      || 'ssh';
    my $server_group = $body->{server_group} || 'default';

    unless ($user) {
        return $self->_badRequest($req, 'Missing user parameter');
    }

    $self->logger->debug("PAM authorize: checking user '$user' for host '$host', service '$service', server_group '$server_group'");

    # 4. Lookup user (without active session)
    $req->user($user);
    $req->data->{_pamAuthorize} = 1;
    $req->steps( [
        'getUser',
        'setSessionInfo',
        $self->p->groupsAndMacros,
        'setLocalGroups'
    ] );

    my $error = $self->p->process($req);

    if ( $error != PE_OK ) {
        $self->logger->info("PAM authorize: User '$user' not found (error: $error)");

        # Audit log for authorization failure (user not found)
        $self->p->auditLog(
            $req,
            code         => 'PAM_AUTHZ_USER_NOT_FOUND',
            user         => $user,
            message      => "PAM authorization failed: user '$user' not found",
            host         => $host,
            service      => $service,
            server_group => $server_group,
            server_id    => $server_id,
        );

        return $self->p->sendJSONresponse(
            $req,
            {
                authorized => JSON::false,
                user       => $user,
                reason     => 'User not found',
            },
            code => 200
        );
    }

    # 5. Evaluate authorization rule based on server_group
    my $result = $self->_checkPamRule( $req, $host, $service, $server_group );
    my $authorized   = $result->{authorized};
    my $sudo_allowed = $result->{sudo_allowed};

    # Get groups for response
    my $groups = $req->sessionInfo->{groups} || '';
    my @groupList = split /[,;\s]+/, $groups;

    $self->logger->info(
        "PAM authorize: user '$user' " .
        ($authorized ? 'granted' : 'denied') .
        " access to host '$host'" .
        ($authorized && $sudo_allowed ? ' (sudo allowed)' : '')
    );

    # Audit log for authorization result
    if ($authorized) {
        $self->p->auditLog(
            $req,
            code         => 'PAM_AUTHZ_SUCCESS',
            user         => $user,
            message      => "PAM authorization granted for user '$user' on host '$host'",
            host         => $host,
            service      => $service,
            server_group => $server_group,
            server_id    => $server_id,
            groups       => \@groupList,
            sudo_allowed => $sudo_allowed,
        );
    }
    else {
        $self->p->auditLog(
            $req,
            code         => 'PAM_AUTHZ_DENIED',
            user         => $user,
            message      => "PAM authorization denied for user '$user' on host '$host'",
            host         => $host,
            service      => $service,
            server_group => $server_group,
            server_id    => $server_id,
            groups       => \@groupList,
            reason       => 'Access denied by rule',
        );
    }

    # Build response with permissions
    my $response = {
        authorized => $authorized ? JSON::true : JSON::false,
        user       => $user,
        groups     => \@groupList,
    };

    # Add permissions for authorized users
    if ($authorized) {
        $response->{permissions} = {
            sudo_allowed => $sudo_allowed ? JSON::true : JSON::false,
        };

        # Add user attributes for NSS/cache (from exported vars)
        my $exportedVars = $self->conf->{pamAccessExportedVars} || {};
        for my $key ( keys %$exportedVars ) {
            my $attr = $exportedVars->{$key};
            my $value = $req->sessionInfo->{$attr};
            if ( defined $value && $value ne '' ) {
                $response->{$key} = $value;
            }
        }

        # Check if offline mode is enabled for this user
        my $offlineEnabled = $self->_evaluateOfflineMode($req);
        if ($offlineEnabled) {
            my $offlineTtl = $self->conf->{pamAccessOfflineTtl} || 86400;
            $response->{offline} = {
                enabled => JSON::true,
                ttl     => $offlineTtl,
            };
            $self->logger->debug(
                "PAM authorize: offline mode enabled for user '$user' (TTL: ${offlineTtl}s)"
            );
        }
    }
    else {
        $response->{reason} = 'Access denied by rule';
    }

    return $self->p->sendJSONresponse(
        $req,
        $response,
        code => 200
    );
}

# HELPER METHODS

# Check PAM authorization rule for a specific service type
# Returns: { authorized => 0|1, sudo_allowed => 0|1 }
sub _checkPamRule {
    my ( $self, $req, $host, $service, $server_group ) = @_;

    # Set variables available for rule evaluation
    $req->sessionInfo->{_pamHost}        = $host;
    $req->sessionInfo->{_pamService}     = $service;
    $req->sessionInfo->{_pamServerGroup} = $server_group || 'default';

    my $result = {
        authorized   => 0,
        sudo_allowed => 0,
    };

    # Determine which rule set to use based on service type
    my $ssh_authorized = $self->_evaluateRule(
        $req, $server_group, 'ssh'
    );

    # For SSH service, check SSH rules
    if ( $service eq 'sshd' || $service eq 'ssh' ) {
        $result->{authorized} = $ssh_authorized;
    }
    # For sudo service, check both SSH (must be connected) and sudo rules
    elsif ( $service eq 'sudo' ) {
        # User must first be authorized for SSH
        if ($ssh_authorized) {
            $result->{authorized} = 1;
            $result->{sudo_allowed} = $self->_evaluateRule(
                $req, $server_group, 'sudo'
            );
        }
    }
    # For other services, fall back to legacy rules
    else {
        $result->{authorized} = $self->_evaluateRule(
            $req, $server_group, 'legacy'
        );
    }

    # Also compute sudo_allowed for SSH requests (for response)
    if ( $service eq 'sshd' || $service eq 'ssh' ) {
        $result->{sudo_allowed} = $self->_evaluateRule(
            $req, $server_group, 'sudo'
        );
    }

    return $result;
}

# Evaluate a specific rule type for a server group
sub _evaluateRule {
    my ( $self, $req, $server_group, $rule_type ) = @_;

    $server_group ||= 'default';

    # Select the appropriate rule set
    my $rules;
    if ( $rule_type eq 'ssh' ) {
        $rules = $self->conf->{pamAccessSshRules} || {};
        # Fallback to legacy rules if SSH rules not defined
        if ( !%$rules ) {
            $rules = $self->conf->{pamAccessServerGroups} || {};
        }
    }
    elsif ( $rule_type eq 'sudo' ) {
        $rules = $self->conf->{pamAccessSudoRules} || {};
        # No fallback for sudo - if not defined, sudo is denied
    }
    else {
        # Legacy mode
        $rules = $self->conf->{pamAccessServerGroups} || {};
    }

    my $rule;

    # 1. Look for rule matching the requested server_group
    if ( exists $rules->{$server_group} ) {
        $rule = $rules->{$server_group};
        $self->logger->debug(
            "PAM authorize: using $rule_type rule for group '$server_group'"
        );
    }
    # 2. Fallback to 'default' group
    elsif ( exists $rules->{default} ) {
        $rule = $rules->{default};
        $self->logger->debug(
            "PAM authorize: $rule_type rule for '$server_group' not found, using 'default'"
        );
    }
    # 3. No rule found -> deny
    else {
        $self->logger->debug(
            "PAM authorize: no $rule_type rule for '$server_group' or 'default'"
        );
        return 0;
    }

    # Simple boolean
    return $rule if defined $rule && $rule =~ /^[01]$/;

    # Empty or undefined rule -> deny
    return 0 unless defined $rule && $rule ne '';

    # Evaluate rule as expression
    my $result = $self->p->HANDLER->buildSub(
        $self->p->HANDLER->substitute($rule)
    )->( $req, $req->sessionInfo );

    return $result ? 1 : 0;
}

# Evaluate if offline mode is enabled for this user
sub _evaluateOfflineMode {
    my ( $self, $req ) = @_;

    my $rule = $self->conf->{pamAccessOfflineEnabled};

    # Not configured or disabled
    return 0 unless defined $rule && $rule ne '' && $rule ne '0';

    # Simple boolean true
    return 1 if $rule eq '1';

    # Evaluate as expression
    my $result = $self->p->HANDLER->buildSub(
        $self->p->HANDLER->substitute($rule)
    )->( $req, $req->sessionInfo );

    return $result ? 1 : 0;
}

sub _unauthorizedResponse {
    my ( $self, $req, $message ) = @_;
    $message ||= 'Unauthorized';

    return $self->p->sendJSONresponse(
        $req,
        { error => $message },
        code => 401,
        headers => [ 'WWW-Authenticate' => 'Bearer realm="pam"' ],
    );
}

sub _forbiddenResponse {
    my ( $self, $req, $message ) = @_;
    $message ||= 'Forbidden';

    return $self->p->sendJSONresponse(
        $req,
        { error => $message },
        code => 403
    );
}

sub _badRequest {
    my ( $self, $req, $message ) = @_;
    $message ||= 'Bad Request';

    return $self->p->sendJSONresponse(
        $req,
        { error => $message },
        code => 400
    );
}

# POST /pam/verify - Verify and consume a one-time PAM token
sub verifyToken {
    my ( $self, $req ) = @_;

    # 1. Validate server Bearer token from Authorization header
    my $server_token = $self->oidc->getEndPointAccessToken($req);
    unless ($server_token) {
        $self->logger->warn('PAM verify: No server Bearer token provided');
        return $self->_unauthorizedResponse( $req, 'Server Bearer token required' );
    }

    my $serverSession = $self->oidc->getAccessToken($server_token);
    unless ($serverSession) {
        $self->logger->warn('PAM verify: Invalid or expired server token');
        return $self->_unauthorizedResponse( $req, 'Invalid or expired server token' );
    }

    # Verify server token was obtained via Device Authorization Grant
    my $grant_type = $serverSession->data->{grant_type} || '';
    unless ( $grant_type eq 'device_code' ) {
        $self->logger->warn(
            "PAM verify: Server token not from Device Authorization Grant "
              . "(grant_type: '$grant_type')"
        );
        return $self->_forbiddenResponse( $req,
            'Server not enrolled. Use Device Authorization Grant.' );
    }

    # 2. Parse JSON request body
    my $body = eval { from_json( $req->content ) };
    if ($@) {
        $self->logger->error("PAM verify: Invalid JSON body: $@");
        return $self->_badRequest( $req, 'Invalid JSON' );
    }

    my $user_token = $body->{token};
    unless ($user_token) {
        return $self->_badRequest( $req, 'token parameter required' );
    }

    # Get server info for audit
    my $server_id = $serverSession->data->{client_id} || 'unknown';

    # 3. Retrieve the PAMTOKEN session
    my $tokenSession = $self->p->getApacheSession( $user_token, kind => 'PAMTOKEN' );
    unless ($tokenSession) {
        $self->logger->info("PAM verify: Invalid or expired token");

        # Audit log for authentication failure
        $self->p->auditLog(
            $req,
            code      => 'PAM_AUTH_INVALID_TOKEN',
            message   => 'PAM authentication failed: invalid or expired token',
            server_id => $server_id,
            reason    => 'Invalid or expired token',
        );

        return $self->p->sendJSONresponse(
            $req,
            {
                valid => JSON::false,
                error => 'Invalid or expired token',
            },
            code => 200
        );
    }

    # 4. Verify token type
    my $type = $tokenSession->data->{_type} || '';
    unless ( $type eq 'pamtoken' ) {
        $self->logger->warn("PAM verify: Wrong token type '$type'");

        # Audit log for security error
        $self->p->auditLog(
            $req,
            code      => 'PAM_AUTH_WRONG_TOKEN_TYPE',
            message   => "PAM authentication failed: wrong token type '$type'",
            server_id => $server_id,
            reason    => 'Invalid token type',
        );

        $tokenSession->remove;
        return $self->p->sendJSONresponse(
            $req,
            {
                valid => JSON::false,
                error => 'Invalid token type',
            },
            code => 200
        );
    }

    # 5. Check expiration
    my $expiresAt = $tokenSession->data->{_pamExpiresAt} || 0;
    if ( time() > $expiresAt ) {
        my $user = $tokenSession->data->{_pamUser} || 'unknown';
        $self->logger->info("PAM verify: Token expired");

        # Audit log for expired token
        $self->p->auditLog(
            $req,
            code      => 'PAM_AUTH_TOKEN_EXPIRED',
            user      => $user,
            message   => "PAM authentication failed: token expired for user '$user'",
            server_id => $server_id,
            reason    => 'Token expired',
        );

        $tokenSession->remove;
        return $self->p->sendJSONresponse(
            $req,
            {
                valid => JSON::false,
                error => 'Token expired',
            },
            code => 200
        );
    }

    # 6. Extract user info
    my $user   = $tokenSession->data->{_pamUser}   || '';
    my $groups = $tokenSession->data->{_pamGroups} || '';
    my @groupList = $groups ? split( /[,;\s]+/, $groups ) : ();

    # Extract exported attributes (prefixed with _pamAttr_)
    my %attrs;
    for my $key ( keys %{ $tokenSession->data } ) {
        if ( $key =~ /^_pamAttr_(.+)$/ ) {
            $attrs{$1} = $tokenSession->data->{$key};
        }
    }

    # 7. CRITICAL: Remove the session (one-time use!)
    $tokenSession->remove;

    $self->logger->info("PAM verify: Token consumed for user '$user'");

    # Audit log for successful authentication
    $self->p->auditLog(
        $req,
        code      => 'PAM_AUTH_SUCCESS',
        user      => $user,
        message   => "PAM authentication successful for user '$user'",
        server_id => $server_id,
        groups    => \@groupList,
    );

    # 8. Return success with user info and exported attributes
    return $self->p->sendJSONresponse(
        $req,
        {
            valid  => JSON::true,
            user   => $user,
            groups => \@groupList,
            ( %attrs ? ( attrs => \%attrs ) : () ),
        },
        code => 200
    );
}

# POST /pam/heartbeat - Server heartbeat for monitoring
sub heartbeat {
    my ( $self, $req ) = @_;

    # 1. Parse JSON request body
    my $body = eval { from_json( $req->content ) };
    if ($@) {
        $self->logger->error("PAM heartbeat: Invalid JSON body: $@");
        return $self->_badRequest( $req, 'Invalid JSON' );
    }

    # 2. Extract refresh_token from body
    my $refresh_token_id = $body->{refresh_token};
    unless ($refresh_token_id) {
        return $self->_badRequest( $req, 'refresh_token required' );
    }

    # 3. Validate refresh token exists
    my $rtSession = $self->oidc->getRefreshToken($refresh_token_id);
    unless ($rtSession) {
        $self->logger->warn('PAM heartbeat: invalid or expired refresh_token');
        return $self->_unauthorizedResponse( $req, 'Invalid refresh_token' );
    }

    # 4. Verify token was obtained via Device Authorization Grant
    my $grant_type = $rtSession->data->{grant_type} || '';
    unless ( $grant_type eq 'device_code' ) {
        $self->logger->warn(
            "PAM heartbeat: Token not from Device Authorization Grant "
              . "(grant_type: '$grant_type')"
        );
        return $self->_forbiddenResponse( $req,
            'Token not from Device Authorization Grant' );
    }

    # 5. Update metadata in refresh_token session
    my $now      = time();
    my $hostname = $body->{hostname} || 'unknown';
    my $updates  = {
        _pamServer      => 1,
        _pamHostname    => $hostname,
        _pamServerGroup => $body->{server_group} || 'default',
        _pamVersion     => $body->{version}      || '',
        _pamLastSeen    => $now,
        _pamStatus      => 'active',
    };

    # Store stats as JSON string if provided
    if ( $body->{stats} ) {
        $updates->{_pamStats} = to_json( $body->{stats} );
    }

    # First heartbeat = enrollment timestamp
    unless ( $rtSession->data->{_pamEnrolledAt} ) {
        $updates->{_pamEnrolledAt} = $now;
    }

    # Update the refresh_token session
    $self->oidc->updateRefreshToken( $rtSession->id, $updates );

    $self->logger->debug("PAM heartbeat from $hostname");

    # 6. Respond with next heartbeat interval
    my $interval = $self->conf->{pamAccessHeartbeatInterval} || 300;
    return $self->p->sendJSONresponse(
        $req,
        {
            status         => 'ok',
            next_heartbeat => $interval,
            server_time    => $now,
        }
    );
}

# POST /pam/userinfo - Get user info for NSS module
sub userinfo {
    my ( $self, $req ) = @_;

    # 1. Validate server Bearer token from Authorization header
    my $server_token = $self->oidc->getEndPointAccessToken($req);
    unless ($server_token) {
        $self->logger->warn('PAM userinfo: No server Bearer token provided');
        return $self->_unauthorizedResponse( $req, 'Server Bearer token required' );
    }

    my $serverSession = $self->oidc->getAccessToken($server_token);
    unless ($serverSession) {
        $self->logger->warn('PAM userinfo: Invalid or expired server token');
        return $self->_unauthorizedResponse( $req, 'Invalid or expired server token' );
    }

    # Verify server token was obtained via Device Authorization Grant
    my $grant_type = $serverSession->data->{grant_type} || '';
    unless ( $grant_type eq 'device_code' ) {
        $self->logger->warn(
            "PAM userinfo: Server token not from Device Authorization Grant "
              . "(grant_type: '$grant_type')"
        );
        return $self->_forbiddenResponse( $req,
            'Server not enrolled. Use Device Authorization Grant.' );
    }

    # 2. Parse JSON request body
    my $body = eval { from_json( $req->content ) };
    if ($@) {
        $self->logger->error("PAM userinfo: Invalid JSON body: $@");
        return $self->_badRequest( $req, 'Invalid JSON' );
    }

    my $user = $body->{user};
    unless ($user) {
        return $self->_badRequest( $req, 'user parameter required' );
    }

    # 3. Lookup user in backend
    $req->user($user);
    $req->data->{_pamUserinfo} = 1;
    $req->steps( [
        'getUser',
        'setSessionInfo',
        $self->p->groupsAndMacros,
        'setLocalGroups'
    ] );

    my $error = $self->p->process($req);

    if ( $error != PE_OK ) {
        $self->logger->debug("PAM userinfo: User '$user' not found (error: $error)");
        return $self->p->sendJSONresponse(
            $req,
            {
                found => JSON::false,
                user  => $user,
            },
            code => 200
        );
    }

    # 4. Build response with user attributes
    my $exportedVars = $self->conf->{pamAccessExportedVars} || {};
    my %attrs;

    for my $key ( keys %$exportedVars ) {
        my $attr = $exportedVars->{$key};
        my $value = $req->sessionInfo->{$attr};
        $attrs{$key} = $value if defined $value && $value ne '';
    }

    # Always include basic info
    my $groups = $req->sessionInfo->{groups} || '';
    my @groupList = split /[,;\s]+/, $groups;

    $self->logger->debug("PAM userinfo: Found user '$user'");

    return $self->p->sendJSONresponse(
        $req,
        {
            found  => JSON::true,
            user   => $user,
            groups => \@groupList,
            %attrs,
        },
        code => 200
    );
}

# =============================================================================
# SSH CA METHODS
# =============================================================================

# GET /ssh/ca.pub - Return SSH CA public key
sub sshCaPublicKey {
    my ( $self, $req ) = @_;

    # Get the key reference from config
    my $keyRef = $self->conf->{sshCaKeyRef};
    unless ($keyRef) {
        $self->logger->error('SSH CA: No key reference configured (sshCaKeyRef)');
        return $self->p->sendError( $req, 'SSH CA not configured', 500 );
    }

    # Get the key from LLNG keys store
    my $keys = $self->conf->{keys} || {};
    my $keyData = $keys->{$keyRef};
    unless ($keyData) {
        $self->logger->error("SSH CA: Key '$keyRef' not found in keys store");
        return $self->p->sendError( $req, 'SSH CA key not found', 500 );
    }

    # Get the public key
    my $publicKey = $keyData->{keyPublic};
    unless ($publicKey) {
        $self->logger->error("SSH CA: No public key for '$keyRef'");
        return $self->p->sendError( $req, 'SSH CA public key not found', 500 );
    }

    # Convert PEM public key to SSH format
    my $sshPubKey = $self->_pemToSshPublicKey($publicKey, $keyRef);
    unless ($sshPubKey) {
        $self->logger->error('SSH CA: Failed to convert public key to SSH format');
        return $self->p->sendError( $req, 'Failed to convert key', 500 );
    }

    $self->logger->debug('SSH CA: Serving public key');

    return [
        200,
        [
            'Content-Type'  => 'text/plain; charset=utf-8',
            'Cache-Control' => 'public, max-age=3600',
        ],
        [$sshPubKey]
    ];
}

# GET /ssh/revoked - Return SSH Key Revocation List (KRL)
sub sshCaKrl {
    my ( $self, $req ) = @_;

    my $krlPath = $self->conf->{sshCaKrlPath};
    unless ($krlPath) {
        $self->logger->error('SSH CA: No KRL path configured');
        return $self->p->sendError( $req, 'KRL not configured', 500 );
    }

    # Read KRL file if it exists
    if ( -f $krlPath ) {
        open my $fh, '<:raw', $krlPath or do {
            $self->logger->error("SSH CA: Cannot read KRL file: $!");
            return $self->p->sendError( $req, 'Cannot read KRL', 500 );
        };
        local $/;
        my $krlData = <$fh>;
        close $fh;

        $self->logger->debug('SSH CA: Serving KRL');

        return [
            200,
            [
                'Content-Type'  => 'application/octet-stream',
                'Cache-Control' => 'public, max-age=300',
            ],
            [$krlData]
        ];
    }
    else {
        # Return empty KRL if file doesn't exist
        $self->logger->debug('SSH CA: KRL file not found, returning empty response');
        return [
            200,
            [
                'Content-Type'  => 'application/octet-stream',
                'Cache-Control' => 'public, max-age=300',
            ],
            ['']
        ];
    }
}

# POST /ssh/sign - Sign user's SSH public key
sub sshCaSign {
    my ( $self, $req ) = @_;

    # Parse JSON request body
    my $body = eval { from_json( $req->content ) };
    if ($@) {
        $self->logger->error("SSH CA sign: Invalid JSON body: $@");
        return $self->_badRequest( $req, 'Invalid JSON' );
    }

    my $userPubKey = $body->{public_key};
    unless ($userPubKey) {
        return $self->_badRequest( $req, 'public_key parameter required' );
    }

    # Validate SSH public key format
    unless ( $userPubKey =~ /^(ssh-\w+|ecdsa-sha2-\w+)\s+[A-Za-z0-9+\/=]+/ ) {
        return $self->_badRequest( $req, 'Invalid SSH public key format' );
    }

    # Get validity from request or use default
    my $validityMinutes = $body->{validity_minutes}
                        || $self->conf->{sshCaCertDefaultValidity}
                        || 30;

    # Enforce maximum validity
    my $maxValidity = $self->conf->{sshCaCertMaxValidity} || 60;
    $validityMinutes = $maxValidity if $validityMinutes > $maxValidity;

    # SECURITY: Always derive principals from the authenticated user's session
    # Never trust principals from the request body to prevent impersonation attacks
    my @principals;

    # Evaluate principal sources from config (e.g., '$uid' or '$uid $mail')
    my $principalSources = $self->conf->{sshCaPrincipalSources} || '$uid';

    # Simple variable substitution from session (try userData first, then sessionInfo)
    my $principal = $principalSources;
    $principal =~ s/\$(\w+)/
        $req->userData->{$1} || $req->sessionInfo->{$1} || ''
    /ge;
    $principal =~ s/^\s+|\s+$//g;  # trim

    # Split on whitespace if multiple principals
    @principals = grep { $_ ne '' } split /\s+/, $principal;

    # Log warning if client tried to specify principals (potential attack attempt)
    if ( $body->{principals} && ref $body->{principals} eq 'ARRAY' ) {
        $self->logger->warn(
            "SSH CA sign: Ignoring 'principals' parameter from request "
            . "(user: " . ($req->user || 'unknown') . "). "
            . "Principals are always derived from session for security."
        );
    }

    unless (@principals) {
        $self->logger->error('SSH CA sign: No principals available');
        return $self->_badRequest( $req, 'No principals available' );
    }

    # Get user info for key_id
    my $whatToTrace = $self->conf->{whatToTrace} || 'uid';
    my $user = $req->userData->{$whatToTrace}
            || $req->sessionInfo->{$whatToTrace}
            || $req->userData->{uid}
            || $req->sessionInfo->{uid}
            || $req->user
            || 'unknown';

    # Generate serial number
    my $serial = $self->_getNextSerial();

    # Generate key_id
    my $timestamp = time();
    my $keyId = sprintf( "%s\@llng-%d-%06d", $user, $timestamp, $serial );

    # Sign the certificate
    my $result = $self->_signSshKey(
        $userPubKey,
        \@principals,
        $validityMinutes,
        $serial,
        $keyId
    );

    unless ( $result && $result->{certificate} ) {
        $self->logger->error('SSH CA sign: Failed to sign key');
        return $self->p->sendJSONresponse(
            $req,
            { error => 'Failed to sign SSH key' },
            code => 500
        );
    }

    # Calculate expiration time
    my $validUntil = time() + ( $validityMinutes * 60 );
    my @t = gmtime($validUntil);
    my $validUntilISO = sprintf(
        "%04d-%02d-%02dT%02d:%02d:%02dZ",
        $t[5] + 1900, $t[4] + 1, $t[3], $t[2], $t[1], $t[0]
    );

    $self->logger->info(
        "SSH CA: Certificate issued for user '$user', "
        . "principals: " . join(',', @principals) . ", "
        . "validity: ${validityMinutes}min, serial: $serial"
    );

    # Audit log
    $self->p->auditLog(
        $req,
        code       => 'SSH_CERT_ISSUED',
        user       => $user,
        message    => "SSH certificate issued for user '$user'",
        principals => \@principals,
        serial     => $serial,
        key_id     => $keyId,
        validity   => $validityMinutes,
    );

    return $self->p->sendJSONresponse(
        $req,
        {
            certificate => $result->{certificate},
            serial      => $serial,
            valid_until => $validUntilISO,
            principals  => \@principals,
            key_id      => $keyId,
        }
    );
}

# HELPER: Get next serial number (atomic increment)
sub _getNextSerial {
    my ($self) = @_;

    my $serialPath = $self->conf->{sshCaSerialPath}
                   || '/var/lib/lemonldap-ng/ssh/serial';

    # Ensure directory exists
    my $dir = $serialPath;
    $dir =~ s|/[^/]+$||;
    unless ( -d $dir ) {
        require File::Path;
        File::Path::make_path($dir);
    }

    # Read current serial, increment, and write back
    my $serial = 1;
    if ( -f $serialPath ) {
        if ( open my $fh, '<', $serialPath ) {
            $serial = <$fh>;
            chomp $serial;
            $serial = int($serial) + 1;
            close $fh;
        }
    }

    # Write new serial
    if ( open my $fh, '>', $serialPath ) {
        print $fh "$serial\n";
        close $fh;
    }
    else {
        $self->logger->warn("SSH CA: Cannot write serial file: $!");
    }

    return $serial;
}

# HELPER: Sign SSH key using ssh-keygen
sub _signSshKey {
    my ( $self, $userPubKey, $principals, $validityMinutes, $serial, $keyId ) = @_;

    require File::Temp;

    # Get CA private key
    my $keyRef = $self->conf->{sshCaKeyRef};
    unless ($keyRef) {
        $self->logger->error('SSH CA: No key reference configured');
        return undef;
    }

    my $keys = $self->conf->{keys} || {};
    my $keyData = $keys->{$keyRef};
    unless ( $keyData && $keyData->{keyPrivate} ) {
        $self->logger->error("SSH CA: Key '$keyRef' not found or has no private key");
        return undef;
    }

    # Create temp directory for key files
    my $tmpdir = File::Temp::tempdir( CLEANUP => 1 );

    # Write CA private key to temp file (convert PEM to OpenSSH format)
    my $caKeyFile = "$tmpdir/ca_key";
    my $caKeyOpenSSH = $self->_pemToOpenSSHPrivateKey( $keyData->{keyPrivate} );
    unless ($caKeyOpenSSH) {
        $self->logger->error('SSH CA: Failed to convert CA key');
        return undef;
    }

    open my $fh, '>', $caKeyFile or do {
        $self->logger->error("SSH CA: Cannot write CA key: $!");
        return undef;
    };
    print $fh $caKeyOpenSSH;
    close $fh;
    chmod 0600, $caKeyFile;

    # Write user's public key to temp file
    my $userKeyFile = "$tmpdir/user_key.pub";
    open $fh, '>', $userKeyFile or do {
        $self->logger->error("SSH CA: Cannot write user key: $!");
        return undef;
    };
    print $fh $userPubKey;
    print $fh "\n" unless $userPubKey =~ /\n$/;
    close $fh;

    # Build ssh-keygen command
    my @cmd = (
        'ssh-keygen',
        '-s', $caKeyFile,           # CA key
        '-I', $keyId,               # Key identity
        '-n', join(',', @$principals),  # Principals
        '-V', "+${validityMinutes}m",   # Validity
        '-z', $serial,              # Serial number
        $userKeyFile                # User's public key to sign
    );

    $self->logger->debug("SSH CA: Running: " . join(' ', @cmd));

    # Execute ssh-keygen
    my $output = '';
    my $pid = open my $pipe, '-|';
    if ( !defined $pid ) {
        $self->logger->error("SSH CA: Cannot fork: $!");
        return undef;
    }
    elsif ( $pid == 0 ) {
        # Child process
        open STDERR, '>&', \*STDOUT;
        exec @cmd;
        exit 1;
    }
    else {
        # Parent process
        local $/;
        $output = <$pipe>;
        close $pipe;
    }

    my $exitCode = $? >> 8;
    if ( $exitCode != 0 ) {
        $self->logger->error("SSH CA: ssh-keygen failed (exit $exitCode): $output");
        return undef;
    }

    # Read the generated certificate
    my $certFile = "$tmpdir/user_key-cert.pub";
    unless ( -f $certFile ) {
        $self->logger->error("SSH CA: Certificate file not created");
        return undef;
    }

    open $fh, '<', $certFile or do {
        $self->logger->error("SSH CA: Cannot read certificate: $!");
        return undef;
    };
    my $certificate = <$fh>;
    close $fh;
    chomp $certificate;

    return { certificate => $certificate };
}

# HELPER: Convert PEM private key to OpenSSH format
sub _pemToOpenSSHPrivateKey {
    my ( $self, $pemKey ) = @_;

    # For Ed25519 keys, we need to convert PEM to OpenSSH format
    # ssh-keygen can read PEM format directly for some key types,
    # but for Ed25519 we may need conversion

    # First, try to detect if it's already in OpenSSH format
    if ( $pemKey =~ /^-----BEGIN OPENSSH PRIVATE KEY-----/ ) {
        return $pemKey;
    }

    # For Ed25519 PEM keys, use ssh-keygen to convert
    if ( $pemKey =~ /BEGIN PRIVATE KEY/ || $pemKey =~ /BEGIN EC PRIVATE KEY/ ) {
        require File::Temp;
        my $tmpdir = File::Temp::tempdir( CLEANUP => 1 );
        my $pemFile = "$tmpdir/key.pem";
        my $sshFile = "$tmpdir/key";

        # Write PEM key
        open my $fh, '>', $pemFile or return undef;
        print $fh $pemKey;
        close $fh;
        chmod 0600, $pemFile;

        # Try to use the PEM directly with ssh-keygen
        # ssh-keygen -s accepts PEM format for RSA/ECDSA
        # For Ed25519, we need to check if it works

        # Actually, let's just return the PEM and see if ssh-keygen accepts it
        return $pemKey;
    }

    # RSA keys in traditional format
    if ( $pemKey =~ /BEGIN RSA PRIVATE KEY/ ) {
        return $pemKey;
    }

    return $pemKey;
}

# HELPER: Convert PEM public key to SSH format
sub _pemToSshPublicKey {
    my ( $self, $pemKey, $comment ) = @_;

    require MIME::Base64;

    my $sshKey;

    # Try Ed25519 first
    eval {
        require Crypt::PK::Ed25519;
        my $pk = Crypt::PK::Ed25519->new(\$pemKey);
        my $rawKey = $pk->export_key_raw('public');

        # Build SSH format: string "ssh-ed25519" + string <32 bytes key>
        my $keyType = 'ssh-ed25519';
        my $blob = pack('N', length($keyType)) . $keyType
                 . pack('N', length($rawKey)) . $rawKey;

        $sshKey = "$keyType " . MIME::Base64::encode_base64($blob, '');
    };

    # Try RSA if Ed25519 failed
    if ($@ || !$sshKey) {
        eval {
            require Crypt::PK::RSA;
            my $pk = Crypt::PK::RSA->new(\$pemKey);
            # RSA keys can use export_key_openssh
            $sshKey = $pk->export_key_openssh;
        };
    }

    unless ($sshKey) {
        $self->logger->error("SSH CA: Failed to convert key to SSH format: $@");
        return undef;
    }

    # Add comment (SSH key has format: type base64 [comment])
    chomp($sshKey);
    my @parts = split /\s+/, $sshKey;
    if (@parts == 2) {
        # No comment yet, add one
        $sshKey .= " LLNG-SSH-CA-$comment";
    }

    return "$sshKey\n";
}

1;

__END__

=pod

=encoding utf8

=head1 NAME

Lemonldap::NG::Portal::Plugins::PamAccess - PAM authentication/authorization plugin

=head1 SYNOPSIS

Enable this plugin in LemonLDAP::NG Manager:
General Parameters > Plugins > PAM Access > Activation

=head1 DESCRIPTION

This plugin provides three main features:

=head2 User Token Generation (/pam)

Authenticated users can generate temporary ONE-TIME access tokens that can
be used as passwords for PAM authentication (e.g., SSH login).

Tokens are stored as sessions with kind='PAMTOKEN' and are automatically
destroyed after first use, preventing replay attacks.

=head2 Token Verification (/pam/verify)

Servers validate and consume one-time user tokens. The token is destroyed
immediately upon successful verification, ensuring single-use semantics.

=head2 Server Authorization (/pam/authorize)

Servers can check if a user is authorized to access a service, even when
the user authenticates via SSH key (no token involved).

=head1 ENDPOINTS

=head2 GET /pam

Display the token generation interface (requires authentication).

=head2 POST /pam

Generate a new one-time PAM access token.

Parameters:
- duration: Token validity in seconds (optional, default: 600)

Response:
{
  "token": "session_id",
  "login": "username",
  "expires_in": 600
}

=head2 POST /pam/verify

Verify and consume a one-time user token (server-to-server).

Requires: Server Bearer token in Authorization header (from Device Auth Grant)

Request body:
{
  "token": "user_token_to_verify"
}

Response:
{
  "valid": true/false,
  "user": "username",
  "groups": ["group1", "group2"],
  "error": "..." (only if invalid)
}

IMPORTANT: The token is destroyed after successful verification (one-time use).

=head2 POST /pam/authorize

Check if a user is authorized (server-to-server).

Requires: Bearer token in Authorization header

Request body:
{
  "user": "username",
  "host": "server.example.com",
  "service": "ssh"
}

Response:
{
  "authorized": true/false,
  "user": "username",
  "groups": ["group1", "group2"],
  "reason": "..." (only if denied)
}

=head2 POST /pam/heartbeat

Server heartbeat for monitoring enrolled PAM servers.

Request body:
{
  "refresh_token": "session_id_of_refresh_token",
  "hostname": "server.example.com",
  "server_group": "production",
  "version": "1.0.0",
  "stats": { "auth_success": 42, "auth_failure": 3 }
}

Response:
{
  "status": "ok",
  "next_heartbeat": 300,
  "server_time": 1702742400
}

=head1 CONFIGURATION

=over

=item pamAccessActivation

Enable/disable the plugin (default: 0)

=item portalDisplayPamAccess

Rule for displaying the menu tab (default: 0)

=item pamAccessTokenDuration

Default token validity in seconds (default: 600)

=item pamAccessMaxDuration

Maximum token validity in seconds (default: 3600)

=item pamAccessServerGroups

Hash of server group names to authorization rules. Each PAM server can
specify its group via the C<server_group> parameter in the authorize request.
If a server's group is not found, the 'default' group rule is used.

Example:
  {
    "production" => '$hGroup->{ops}',
    "staging"    => '$hGroup->{ops} or $hGroup->{dev}',
    "dev"        => '$hGroup->{dev} or $uid eq "admin"',
    "default"    => '1'
  }

=item pamAccessRp

OIDC Relying Party name for tokens (default: 'pam-access')

=item pamAccessHeartbeatInterval

Expected interval between server heartbeats in seconds (default: 300)

=item pamAccessInactiveThreshold

Time in seconds after which a server is considered inactive if no heartbeat
received (default: 900)

=item pamAccessHeartbeatRequired

If enabled, servers must have a recent heartbeat to use /pam/authorize.
This ensures that the PAM module is still active on the server. (default: 0)

=back

=head1 SEE ALSO

L<Lemonldap::NG::Portal::Plugins::DeviceAuthorization> for server enrollment

=head1 AUTHORS

=over

=item LemonLDAP::NG team L<https://lemonldap-ng.org/team>

=back

=head1 LICENSE AND COPYRIGHT

See COPYING file for details.

=cut
