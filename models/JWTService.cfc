/**
 * JWTService — INTERNAL low-level JWT engine for cf-token-manager.
 *
 * This is the "JWT Engine" layer. It only knows how to encode, decode and verify
 * a single JWT. It has no concept of access vs refresh tokens, expiry policy or
 * authentication — that lives in TokenManager.cfc (the lifecycle layer).
 *
 * Host applications should NOT inject this service directly; use TokenManager instead.
 *
 * Signing is performed with the JVM's javax.crypto.Mac / SecretKeySpec classes so the
 * behaviour is identical across Adobe ColdFusion, BoxLang and Lucee.
 *
 * Supported algorithms: HS256, HS384, HS512
 */
component singleton accessors="true" {

	variables.algorithmMap = {
		"HS256" : "HmacSHA256",
		"HS384" : "HmacSHA384",
		"HS512" : "HmacSHA512"
	};

	/**
	 * Encode a payload struct into a signed JWT string (header.payload.signature).
	 *
	 * @payload   The claims to embed in the token body.
	 * @key       The secret used to sign the token.
	 * @algorithm One of HS256, HS384, HS512.
	 */
	string function encode( required struct payload, required string key, string algorithm = "HS512" ){
		assertAlgorithm( arguments.algorithm );

		var header       = { "typ" : "JWT", "alg" : arguments.algorithm };
		var encHeader    = base64UrlEncode( serializeJSON( header ) );
		var encPayload   = base64UrlEncode( serializeJSON( arguments.payload ) );
		var signingInput = encHeader & "." & encPayload;

		return signingInput & "." & sign( signingInput, arguments.key, arguments.algorithm );
	}

	/**
	 * Decode a JWT body WITHOUT verifying the signature.
	 * Throws cftokenmanager.MalformedToken if the structure is invalid.
	 *
	 * @token A JWT string with three dot-delimited segments.
	 */
	struct function decode( required string token ){
		var parts = listToArray( arguments.token, "." );
		if ( arrayLen( parts ) != 3 ) {
			throw(
				type    = "cftokenmanager.MalformedToken",
				message = "A JWT must contain exactly three segments separated by dots."
			);
		}

		try {
			return deserializeJSON( base64UrlDecode( parts[ 2 ] ) );
		} catch ( any e ) {
			throw(
				type    = "cftokenmanager.MalformedToken",
				message = "The token payload could not be decoded: #e.message#"
			);
		}
	}

	/**
	 * Verify the signature of a JWT against the supplied key/algorithm.
	 * Returns true/false only — it does NOT inspect expiry or claims.
	 *
	 * @token     A JWT string with three dot-delimited segments.
	 * @key       The secret the token should have been signed with.
	 * @algorithm One of HS256, HS384, HS512.
	 */
	boolean function verifySignature( required string token, required string key, string algorithm = "HS512" ){
		var parts = listToArray( arguments.token, "." );
		if ( arrayLen( parts ) != 3 ) {
			return false;
		}
		var expected = sign( parts[ 1 ] & "." & parts[ 2 ], arguments.key, arguments.algorithm );
		// Constant-time comparison to avoid timing attacks on the signature.
		return constantTimeEquals( expected, parts[ 3 ] );
	}

	/* --------------------------------------------------------------------- */
	/* Internals                                                             */
	/* --------------------------------------------------------------------- */

	private void function assertAlgorithm( required string algorithm ){
		if ( !structKeyExists( variables.algorithmMap, arguments.algorithm ) ) {
			throw(
				type    = "cftokenmanager.UnsupportedAlgorithm",
				message = "Unsupported algorithm [#arguments.algorithm#]. Use one of: #structKeyList( variables.algorithmMap )#."
			);
		}
	}

	/**
	 * Produce a base64url HMAC signature using the JVM crypto classes.
	 */
	private string function sign( required string msg, required string key, required string algorithm ){
		assertAlgorithm( arguments.algorithm );
		var javaAlg = variables.algorithmMap[ arguments.algorithm ];
		var keySpec = createObject( "java", "javax.crypto.spec.SecretKeySpec" ).init(
			arguments.key.getBytes( "UTF-8" ),
			javaAlg
		);
		var mac = createObject( "java", "javax.crypto.Mac" ).getInstance( javaAlg );
		mac.init( keySpec );
		return base64UrlEncodeBytes( mac.doFinal( arguments.msg.getBytes( "UTF-8" ) ) );
	}

	private string function base64UrlEncode( required string value ){
		return base64UrlEncodeBytes( charsetDecode( arguments.value, "utf-8" ) );
	}

	private string function base64UrlEncodeBytes( required any bytes ){
		return reReplace(
			reReplace( reReplace( toBase64( arguments.bytes ), "\+", "-", "ALL" ), "/", "_", "ALL" ),
			"=",
			"",
			"ALL"
		);
	}

	private string function base64UrlDecode( required string value ){
		var b64    = reReplace( reReplace( arguments.value, "-", "+", "ALL" ), "_", "/", "ALL" );
		var pad    = ( 4 - ( len( b64 ) % 4 ) ) % 4;
		var padded = b64 & repeatString( "=", pad );
		return charsetEncode( binaryDecode( padded, "base64" ), "utf-8" );
	}

	/**
	 * Length-constant string comparison to mitigate timing attacks.
	 */
	private boolean function constantTimeEquals( required string a, required string b ){
		if ( len( arguments.a ) != len( arguments.b ) ) {
			return false;
		}
		var result = 0;
		for ( var i = 1; i <= len( arguments.a ); i++ ) {
			result = bitOr( result, bitXor( asc( mid( arguments.a, i, 1 ) ), asc( mid( arguments.b, i, 1 ) ) ) );
		}
		return result == 0;
	}

}
