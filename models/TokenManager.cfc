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
 *
 * Responsibilities handled automatically:
 *   - Header construction        ({ typ, alg })
 *   - Access payload + 15m expiry
 *   - Refresh payload + 30d expiry
 *   - iat / exp / iss claims
 *   - Java HMAC signing (delegated to JWTService)
 *   - Type checking (access vs refresh)
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

		var accessClaims = stripReservedClaims( payload );
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

		if ( !structKeyExists( base, "sub" ) ) {
			throw(
				type    = "cftokenmanager.InvalidSubject",
				message = "issue() requires the subject struct to contain an `id` or `sub` key."
			);
		}

		return base;
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
