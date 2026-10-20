/**
 * TokenManager — PUBLIC API for cf-token-manager.
 *
 * This is the "lifecycle" layer that sits on top of the low-level JWTService engine.
 * The host application only ever talks to this component:
 *
 *     property name="tokenManager" inject="TokenManager@cf-token-manager";
 *
 *     var tokens = tokenManager.issue( { id : 101, role : "admin" } );
 *     // → { accessToken : "...", refreshToken : "..." }
 *
 *     tokenManager.verify( accessToken );                 // boolean
 *     tokenManager.decode( accessToken );                 // struct of claims
 *     tokenManager.refresh( refreshToken );               // { accessToken : "..." }
 *     tokenManager.authorize( accessToken, "admin" );     // trusted claims or throws
 *
 * Responsibilities handled automatically:
 *   - Header construction        ({ typ, alg })
 *   - Access payload + 15m expiry
 *   - Refresh payload + 30d expiry
 *   - iat / exp / iss claims
 *   - Java HMAC signing (delegated to JWTService)
 *   - Type checking (access vs refresh)
 *   - Role normalization and access control (RBAC)
 *
 * Control claims reserved by this package: sub, type, iat, exp, iss.
 */
component singleton accessors="true" {

	// Injected from ModuleConfig settings (overridable by the host app).
	property name="settings" inject="coldbox:moduleSettings:cf-token-manager";
	property name="jwt"      inject="JWTService@cf-token-manager";
	property name="log"      inject="logbox:logger:{this}";

	// Claims that the package manages itself and strips before re-issuing.
	variables.RESERVED_CLAIMS = [ "type", "iat", "exp", "iss" ];

	/* --------------------------------------------------------------------- */
	/* PUBLIC API                                                            */
	/* --------------------------------------------------------------------- */

	/**
	 * issue() — mint a fresh access + refresh token pair for a subject.
	 *
	 * @subject A struct of business claims, e.g. { id : 101, role : "admin" }.
	 *          An `id` key (or `sub`) becomes the JWT subject ("sub"). Every other
	 *          key (role, email, ...) is carried into the token verbatim.
	 *
	 * @return  { accessToken : "<jwt>", refreshToken : "<jwt>" }
	 */
	struct function issue( required struct subject ){
		var base = normalizeSubject( arguments.subject );
		var now  = epochSeconds();

		var accessClaims = duplicate( base );
		accessClaims[ "type" ] = "access";
		accessClaims[ "iat" ]  = now;
		accessClaims[ "exp" ]  = epoch( now + int( settings.accessTokenExpiry ) );
		accessClaims[ "iss" ]  = settings.issuer;

		var refreshClaims = duplicate( base );
		refreshClaims[ "type" ] = "refresh";
		refreshClaims[ "iat" ]  = now;
		refreshClaims[ "exp" ]  = epoch( now + int( settings.refreshTokenExpiry ) );
		refreshClaims[ "iss" ]  = settings.issuer;

		log.info( "Issued token pair for subject [#( base.sub ?: "?" )#]." );

		return {
			"accessToken"  : jwt.encode( accessClaims, settings.secret, settings.algorithm ),
			"refreshToken" : jwt.encode( refreshClaims, settings.secret, settings.algorithm )
		};
	}

	/**
	 * verify() — boolean check that a token is authentic, unexpired and of the
	 * expected type. Never throws.
	 *
	 * @token A JWT string.
	 * @type  Expected token type: "access" (default) or "refresh".
	 */
	boolean function verify( required string token, string type = "access" ){
		try {
			validate( arguments.token, arguments.type );
			return true;
		} catch ( any e ) {
			return false;
		}
	}

	/**
	 * decode() — return the claims struct of a token WITHOUT verifying it.
	 * Use verify() first if you need to trust the result.
	 *
	 * @token A JWT string.
	 */
	struct function decode( required string token ){
		return jwt.decode( arguments.token );
	}

	/**
	 * refresh() — exchange a valid refresh token for a brand-new access token.
	 *
	 * @refreshToken A JWT previously issued as the refresh token.
	 * @return       { accessToken : "<new jwt>" }
	 * @throws       cftokenmanager.* when the refresh token is invalid/expired/wrong type.
	 */
	struct function refresh( required string refreshToken ){
		var payload = validate( arguments.refreshToken, "refresh" );
		var now     = epochSeconds();

		var accessClaims = normalizeRoleClaims( stripReservedClaims( payload ) );
		accessClaims[ "type" ] = "access";
		accessClaims[ "iat" ]  = now;
		accessClaims[ "exp" ]  = epoch( now + int( settings.accessTokenExpiry ) );
		accessClaims[ "iss" ]  = settings.issuer;

		log.info( "Refreshed access token for subject [#( accessClaims.sub ?: "?" )#]." );

		return {
			"accessToken" : jwt.encode( accessClaims, settings.secret, settings.algorithm )
		};
	}

	/* --------------------------------------------------------------------- */
	/* DIAGNOSTICS — used by handlers to build precise error responses        */
	/* --------------------------------------------------------------------- */

	/**
	 * validate() — strict verification that THROWS a typed exception describing
	 * exactly why a token is not acceptable. Returns the decoded claims on success.
	 *
	 * Exception types:
	 *   cftokenmanager.MalformedToken     — not a 3-segment JWT / unparseable body
	 *   cftokenmanager.InvalidSignature   — signature does not match the secret
	 *   cftokenmanager.ExpiredToken       — exp claim is in the past
	 *   cftokenmanager.InvalidTokenType   — token type != expected type
	 *
	 * @token A JWT string.
	 * @type  Expected token type ("access" or "refresh").
	 */
	struct function validate( required string token, string type = "access" ){
		if ( !len( trim( arguments.token ) ) ) {
			throw( type = "cftokenmanager.MissingToken", message = "No token was provided." );
		}

		if ( listLen( arguments.token, "." ) != 3 ) {
			throw( type = "cftokenmanager.MalformedToken", message = "A JWT must contain exactly three segments separated by dots." );
		}

		if ( !jwt.verifySignature( arguments.token, settings.secret, settings.algorithm ) ) {
			throw( type = "cftokenmanager.InvalidSignature", message = "Token signature verification failed." );
		}

		// Safe to read claims now that the signature is trusted.
		var payload = jwt.decode( arguments.token );

		if ( structKeyExists( payload, "exp" ) && epochSeconds() >= payload.exp ) {
			throw( type = "cftokenmanager.ExpiredToken", message = "Token expired at #payload.exp# (epoch seconds)." );
		}

		if ( len( arguments.type ) && ( payload.type ?: "" ) != arguments.type ) {
			throw(
				type    = "cftokenmanager.InvalidTokenType",
				message = "Expected a [#arguments.type#] token but received [#( payload.type ?: "unknown" )#]."
			);
		}

		return payload;
	}

	/**
	 * diagnose() — non-throwing companion to validate(). Returns a struct describing
	 * the verification outcome so handlers can return clean JSON error bodies.
	 *
	 * @return { valid : boolean, code : "VALID|MISSING_TOKEN|MALFORMED_TOKEN|INVALID_SIGNATURE|TOKEN_EXPIRED|INVALID_TOKEN_TYPE", message : "..." }
	 */
	struct function diagnose( required string token, string type = "access" ){
		try {
			validate( arguments.token, arguments.type );
			return { "valid" : true, "code" : "VALID", "message" : "Token is valid." };
		} catch ( cftokenmanager.MissingToken e ) {
			return { "valid" : false, "code" : "MISSING_TOKEN", "message" : e.message };
		} catch ( cftokenmanager.MalformedToken e ) {
			return { "valid" : false, "code" : "MALFORMED_TOKEN", "message" : e.message };
		} catch ( cftokenmanager.InvalidSignature e ) {
			return { "valid" : false, "code" : "INVALID_SIGNATURE", "message" : e.message };
		} catch ( cftokenmanager.ExpiredToken e ) {
			return { "valid" : false, "code" : "TOKEN_EXPIRED", "message" : e.message };
		} catch ( cftokenmanager.InvalidTokenType e ) {
			return { "valid" : false, "code" : "INVALID_TOKEN_TYPE", "message" : e.message };
		} catch ( any e ) {
			return { "valid" : false, "code" : "INVALID_TOKEN", "message" : e.message };
		}
	}

	/**
	 * hasRole() - non-throwing convenience check for one role.
	 *
	 * A false result means either that the token is invalid or that the user does
	 * not have the requested role. Use authorize() or diagnoseAuthorization() when
	 * the caller needs to distinguish those cases.
	 */
	boolean function hasRole( required string token, required string requiredRole, string type = "access" ){
		return hasAnyRole( arguments.token, [ arguments.requiredRole ], arguments.type );
	}

	/**
	 * hasAnyRole() - true when a valid token contains at least one requested role.
	 */
	boolean function hasAnyRole( required string token, required any requiredRoles, string type = "access" ){
		try {
			authorize( arguments.token, arguments.requiredRoles, "any", arguments.type );
			return true;
		} catch ( any e ) {
			return false;
		}
	}

	/**
	 * hasAllRoles() - true when a valid token contains every requested role.
	 */
	boolean function hasAllRoles( required string token, required any requiredRoles, string type = "access" ){
		try {
			authorize( arguments.token, arguments.requiredRoles, "all", arguments.type );
			return true;
		} catch ( any e ) {
			return false;
		}
	}

	/**
	 * authorize() - validate the token and enforce an RBAC role requirement.
	 *
	 * @requiredRoles A role string or array of role strings.
	 * @mode          "any" requires one matching role; "all" requires every role.
	 * @type          Expected token type. Authorization defaults to access tokens.
	 * @return        Trusted token claims when authorization succeeds.
	 * @throws        Authentication exceptions from validate(), or
	 *                cftokenmanager.InsufficientRole when the token is valid but
	 *                does not satisfy the role requirement.
	 */
	struct function authorize( required string token, required any requiredRoles, string mode = "any", string type = "access" ){
		var claims       = validate( arguments.token, arguments.type );
		var expectedMode = lCase( trim( arguments.mode ) );
		var requested    = normalizeRoleList( arguments.requiredRoles, false, "required roles" );
		var actual       = rolesFromClaims( claims );
		var matched      = 0;

		if ( !listFindNoCase( "any,all", expectedMode ) ) {
			throw(
				type    = "cftokenmanager.InvalidAuthorizationMode",
				message = "Authorization mode must be [any] or [all]."
			);
		}

		for ( var requiredRole in requested ) {
			if ( arrayFindNoCase( actual, requiredRole ) ) {
				matched++;
			}
		}

		var authorized = expectedMode == "all"
			? matched == arrayLen( requested )
			: matched > 0;

		if ( !authorized ) {
			throw(
				type    = "cftokenmanager.InsufficientRole",
				message = "The token does not satisfy the required role(s): [#arrayToList( requested, ", " )#]."
			);
		}

		return claims;
	}

	/**
	 * diagnoseAuthorization() - non-throwing companion to authorize().
	 *
	 * Authentication failures remain distinguishable from authorization failures:
	 * invalid/missing tokens should produce a 401, while a valid token without the
	 * required role should produce a 403.
	 */
	struct function diagnoseAuthorization( required string token, required any requiredRoles, string mode = "any", string type = "access" ){
		try {
			var claims = authorize( arguments.token, arguments.requiredRoles, arguments.mode, arguments.type );
			return {
				"valid"      : true,
				"authorized" : true,
				"code"       : "AUTHORIZED",
				"message"    : "Token is valid and authorized.",
				"claims"     : claims
			};
		} catch ( cftokenmanager.MissingToken e ) {
			return authorizationDiagnosis( false, "MISSING_TOKEN", e.message );
		} catch ( cftokenmanager.MalformedToken e ) {
			return authorizationDiagnosis( false, "MALFORMED_TOKEN", e.message );
		} catch ( cftokenmanager.InvalidSignature e ) {
			return authorizationDiagnosis( false, "INVALID_SIGNATURE", e.message );
		} catch ( cftokenmanager.ExpiredToken e ) {
			return authorizationDiagnosis( false, "TOKEN_EXPIRED", e.message );
		} catch ( cftokenmanager.InvalidTokenType e ) {
			return authorizationDiagnosis( false, "INVALID_TOKEN_TYPE", e.message );
		} catch ( cftokenmanager.InsufficientRole e ) {
			return authorizationDiagnosis( true, "INSUFFICIENT_ROLE", e.message );
		} catch ( any e ) {
			return authorizationDiagnosis( false, "INVALID_AUTHORIZATION", e.message );
		}
	}

	/* --------------------------------------------------------------------- */
	/* Internals                                                             */
	/* --------------------------------------------------------------------- */

	/**
	 * Normalise an incoming subject struct:
	 *   - lowercase every claim name so tokens are predictable across CF engines
	 *     (Adobe CF uppercases unquoted struct keys, which would otherwise leak as "ROLE")
	 *   - map `id` → `sub`
	 *   - strip any reserved control claims a caller tried to set
	 */
	private struct function normalizeSubject( required struct subject ){
		var src  = duplicate( arguments.subject );
		var base = {};
		for ( var key in src ) {
			base[ lCase( key ) ] = src[ key ];
		}

		if ( !structKeyExists( base, "sub" ) && structKeyExists( base, "id" ) ) {
			base[ "sub" ] = base.id;
		}
		structDelete( base, "id" );

		base = stripReservedClaims( base );
		base = normalizeRoleClaims( base );

		if ( !structKeyExists( base, "sub" ) ) {
			throw(
				type    = "cftokenmanager.InvalidSubject",
				message = "issue() requires the subject struct to contain an `id` or `sub` key."
			);
		}

		return base;
	}

	/**
	 * Normalize the legacy singular role claim and the v2 roles array into one
	 * predictable representation. The singular role is retained for callers that
	 * still read it, while roles is the canonical RBAC claim.
	 */
	private struct function normalizeRoleClaims( required struct claims ){
		var clean      = duplicate( arguments.claims );
		var normalized = [];

		if ( structKeyExists( clean, "roles" ) ) {
			var declaredRoles = normalizeRoleList( clean.roles, true, "roles" );
			for ( var declaredRole in declaredRoles ) {
				if ( !arrayFindNoCase( normalized, declaredRole ) ) {
					arrayAppend( normalized, declaredRole );
				}
			}
		}

		if ( structKeyExists( clean, "role" ) ) {
			var legacyRoles = normalizeRoleList( clean.role, true, "role" );
			for ( var legacyRole in legacyRoles ) {
				if ( !arrayFindNoCase( normalized, legacyRole ) ) {
					arrayAppend( normalized, legacyRole );
				}
			}
		}

		if ( arrayLen( normalized ) ) {
			clean[ "roles" ] = normalized;
			clean[ "role" ]  = normalized[ 1 ];
		} else {
			structDelete( clean, "roles" );
			structDelete( clean, "role" );
		}

		return clean;
	}

	/**
	 * Convert a single role or an array of roles into normalized role names.
	 */
	private array function normalizeRoleList( required any roles, boolean allowEmpty = false, string label = "roles" ){
		var rawRoles = isArray( arguments.roles ) ? arguments.roles : [ arguments.roles ];
		var result   = [];

		for ( var role in rawRoles ) {
			if ( !isSimpleValue( role ) ) {
				throw(
					type    = "cftokenmanager.InvalidRoleClaim",
					message = "Each value in [#arguments.label#] must be a string."
				);
			}

			var normalizedRole = lCase( trim( toString( role ) ) );
			if ( !len( normalizedRole ) ) {
				if ( !arguments.allowEmpty ) {
					throw(
						type    = "cftokenmanager.InvalidRoleRequirement",
						message = "At least one non-empty role is required."
					);
				}
				continue;
			}

			if ( !arrayFindNoCase( result, normalizedRole ) ) {
				arrayAppend( result, normalizedRole );
			}
		}

		if ( !arguments.allowEmpty && !arrayLen( result ) ) {
			throw(
				type    = "cftokenmanager.InvalidRoleRequirement",
				message = "At least one non-empty role is required."
			);
		}

		return result;
	}

	/**
	 * Read both the canonical roles claim and the legacy role claim. This keeps
	 * tokens issued before RBAC was added compatible with the new checks.
	 */
	private array function rolesFromClaims( required struct claims ){
		var roles = [];

		if ( structKeyExists( arguments.claims, "roles" ) ) {
			var declaredRoles = normalizeRoleList( arguments.claims.roles, true, "roles" );
			for ( var declaredRole in declaredRoles ) {
				if ( !arrayFindNoCase( roles, declaredRole ) ) {
					arrayAppend( roles, declaredRole );
				}
			}
		}

		if ( structKeyExists( arguments.claims, "role" ) ) {
			var legacyRoles = normalizeRoleList( arguments.claims.role, true, "role" );
			for ( var legacyRole in legacyRoles ) {
				if ( !arrayFindNoCase( roles, legacyRole ) ) {
					arrayAppend( roles, legacyRole );
				}
			}
		}

		return roles;
	}

	private struct function authorizationDiagnosis( required boolean valid, required string code, required string message ){
		return {
			"valid"      : arguments.valid,
			"authorized" : false,
			"code"       : arguments.code,
			"message"    : arguments.message
		};
	}

	private struct function stripReservedClaims( required struct claims ){
		var clean = duplicate( arguments.claims );
		for ( var key in variables.RESERVED_CLAIMS ) {
			structDelete( clean, key );
		}
		return clean;
	}

	private numeric function epochSeconds(){
		return epoch( createObject( "java", "java.lang.System" ).currentTimeMillis() / 1000 );
	}

	/**
	 * Coerce a value to a Java long so serializeJSON renders a plain integer
	 * (NumericDate), never scientific notation like 1.78E9.
	 */
	private numeric function epoch( required numeric value ){
		return javacast( "long", int( arguments.value ) );
	}

}
