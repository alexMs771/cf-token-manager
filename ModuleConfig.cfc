/**
 * cf-token-manager — ColdBox Module Configuration
 *
 * Registers the JWT token-lifecycle services and exposes their configuration.
 *
 * Models are auto-mapped under the module namespace, so the public service can be
 * injected anywhere in the host application with:
 *
 *     property name="tokenManager" inject="TokenManager@cf-token-manager";
 *
 * Settings can be overridden by the host app inside `config/Coldbox.cfc`:
 *
 *     moduleSettings = {
 *         "cf-token-manager" : {
 *             secret             : getSystemSetting( "TOKEN_SECRET" ),
 *             algorithm          : "HS512",
 *             accessTokenExpiry  : 900,
 *             refreshTokenExpiry : 2592000,
 *             issuer             : "my-app"
 *         }
 *     };
 */
component {

	this.title         = "CF Token Manager";
	this.author        = "JWTPOC";
	this.webURL        = "";
	this.description   = "JWT token lifecycle manager with access, refresh, and RBAC authorization APIs.";
	this.version       = "2.0.0";

	// Module mapping + model namespace
	this.modelNamespace = "cf-token-manager";
	this.cfmapping      = "cftokenmanager";

	// No inbound HTTP routes — this is a service-only module
	this.entryPoint     = "";
	this.autoMapModels  = true;

	function configure(){
		// Default settings — override these from the host app's moduleSettings.
		settings = {
			// HMAC secret used to sign every token. ALWAYS override in production.
			secret             : "cf-token-manager-default-secret-change-me",
			// Supported: HS256, HS384, HS512
			algorithm          : "HS512",
			// Access token lifetime in seconds (default 15 minutes)
			accessTokenExpiry  : 900,
			// Refresh token lifetime in seconds (default 30 days)
			refreshTokenExpiry : 2592000,
			// Optional issuer ("iss") claim stamped on every token
			issuer             : "cf-token-manager"
		};
	}

	function onLoad(){
		log.info( "cf-token-manager module loaded. Algorithm=#settings.algorithm#, accessTTL=#settings.accessTokenExpiry#s, refreshTTL=#settings.refreshTokenExpiry#s." );
	}

}
