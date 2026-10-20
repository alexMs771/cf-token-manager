component extends="testbox.system.BaseSpec" {

	function beforeAll() {
		variables.tokenManager = new cftokenmanager.models.TokenManager();
		variables.tokenManager.setSettings({
			secret             : "unit-test-secret",
			algorithm          : "HS512",
			accessTokenExpiry  : 900,
			refreshTokenExpiry : 2592000,
			issuer             : "cf-token-manager-tests"
		});
		variables.tokenManager.setJwt( new cftokenmanager.models.JWTService() );
		variables.tokenManager.setLog( new tests.helpers.LoggerStub() );
	}

	function run() {
		describe( "TokenManager", function(){
			it( "issues access and refresh tokens with normalized claims", function(){
				var pair = variables.tokenManager.issue({
					id    : "user-101",
					roles : [ "Admin", "finance", "admin" ]
				});
				var accessClaims  = variables.tokenManager.decode( pair.accessToken );
				var refreshClaims = variables.tokenManager.decode( pair.refreshToken );

				expect( structKeyExists( pair, "accessToken" ) ).toBeTrue();
				expect( structKeyExists( pair, "refreshToken" ) ).toBeTrue();
				expect( accessClaims.sub ).toBe( "user-101" );
				expect( accessClaims.type ).toBe( "access" );
				expect( accessClaims.role ).toBe( "admin" );
				expect( arrayLen( accessClaims.roles ) ).toBe( 2 );
				expect( accessClaims.roles[ 1 ] ).toBe( "admin" );
				expect( accessClaims.roles[ 2 ] ).toBe( "finance" );
				expect( refreshClaims.type ).toBe( "refresh" );
			} );

			it( "verifies tokens and rejects the wrong token type", function(){
				var pair = variables.tokenManager.issue({ id : "user-102" });

				expect( variables.tokenManager.verify( pair.accessToken ) ).toBeTrue();
				expect( variables.tokenManager.verify( pair.refreshToken ) ).toBeFalse();
				expect( variables.tokenManager.verify( pair.refreshToken, "refresh" ) ).toBeTrue();
			} );

			it( "refreshes a token while preserving roles", function(){
				var pair = variables.tokenManager.issue({
					id    : "user-103",
					roles : [ "admin", "finance" ]
				});
				var refreshed = variables.tokenManager.refresh( pair.refreshToken );
				var claims    = variables.tokenManager.validate( refreshed.accessToken );

				expect( claims.type ).toBe( "access" );
				expect( arrayLen( claims.roles ) ).toBe( 2 );
				expect( claims.roles[ 1 ] ).toBe( "admin" );
				expect( claims.roles[ 2 ] ).toBe( "finance" );
			} );

			it( "diagnoses invalid tokens without throwing", function(){
				var result = variables.tokenManager.diagnose( "not.a.valid-token" );

				expect( result.valid ).toBeFalse();
				expect( result.code ).toBe( "INVALID_SIGNATURE" );
			} );

			it( "supports single, any, and all role checks", function(){
				var pair = variables.tokenManager.issue({
					id    : "admin-101",
					roles : [ "admin", "finance" ]
				});

				expect( variables.tokenManager.hasRole( pair.accessToken, "ADMIN" ) ).toBeTrue();
				expect( variables.tokenManager.hasAnyRole( pair.accessToken, [ "manager", "finance" ] ) ).toBeTrue();
				expect( variables.tokenManager.hasAllRoles( pair.accessToken, [ "admin", "finance" ] ) ).toBeTrue();
				expect( variables.tokenManager.hasAllRoles( pair.accessToken, [ "admin", "manager" ] ) ).toBeFalse();
			} );

			it( "returns trusted claims when authorization succeeds", function(){
				var pair   = variables.tokenManager.issue({ id : "admin-102", role : "admin" });
				var claims = variables.tokenManager.authorize( pair.accessToken, "admin" );

				expect( claims.sub ).toBe( "admin-102" );
				expect( claims.type ).toBe( "access" );
			} );

			it( "distinguishes insufficient role from invalid authentication", function(){
				var pair    = variables.tokenManager.issue({ id : "user-104", role : "employee" });
				var denied  = variables.tokenManager.diagnoseAuthorization( pair.accessToken, "admin" );
				var invalid = variables.tokenManager.diagnoseAuthorization( "not.a.valid-token", "admin" );

				expect( denied.valid ).toBeTrue();
				expect( denied.authorized ).toBeFalse();
				expect( denied.code ).toBe( "INSUFFICIENT_ROLE" );
				expect( invalid.valid ).toBeFalse();
				expect( invalid.authorized ).toBeFalse();
				expect( invalid.code ).toBe( "INVALID_SIGNATURE" );
			} );

			it( "rejects a refresh token for access-token authorization", function(){
				var pair   = variables.tokenManager.issue({ id : "user-105", role : "admin" });
				var result = variables.tokenManager.diagnoseAuthorization( pair.refreshToken, "admin" );

				expect( result.valid ).toBeFalse();
				expect( result.authorized ).toBeFalse();
				expect( result.code ).toBe( "INVALID_TOKEN_TYPE" );
			} );
		} );
	}

}
