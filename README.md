# cf-token-manager

A complete **JWT token lifecycle manager** for CFML / ColdBox applications.

Existing JWT packages stop at `encode()` / `decode()` / `verify()` and leave the
developer to build payloads, expiry and refresh flows by hand. `cf-token-manager`
wraps that low-level engine with an authentication-aware API:

```cfml
issue()    // mint an access + refresh token pair
verify()   // is this token authentic, unexpired and the right type?
refresh()  // swap a refresh token for a new access token
decode()   // read the claims of a token
authorize() // validate a token and enforce an RBAC role requirement
```

Header construction, access/refresh payloads, automatic expiry and Java-based HMAC
signing are all handled internally.

## Architecture

```
TokenManager.cfc   ← public lifecycle API (issue/verify/refresh/decode)
        │
        ▼
JWTService.cfc     ← internal JWT engine (encode/decode/verifySignature + Java crypto)
```

`JWTService` is internal — host apps should only inject `TokenManager`.

## Installation (local / private package)

This package is intended to be developed locally and installed into a host app
**without publishing to ForgeBox**:

```bash
# from the host application root
box install ./packages/cf-token-manager
```

CommandBox copies it into the app's module path (`lib/modules/cf-token-manager`) and
ColdBox auto-loads it. To publish later, set `"private": false` in `box.json` and run
`box publish`.

## Usage

Inject the manager via the module namespace:

```cfml
property name="tokenManager" inject="TokenManager@cf-token-manager";
```

### Issue tokens (login)

```cfml
var tokens = tokenManager.issue( { id : 101, role : "admin" } );
// {
//   "accessToken"  : "eyJ0eX...",   // type=access,  exp=+15m
//   "refreshToken" : "eyJ0eX..."    // type=refresh, exp=+30d
// }
```

The `id` key becomes the JWT `sub` claim; all other keys (e.g. `role`) are carried
into the token verbatim.

### Role-based access control

The legacy singular `role` claim remains supported. New code may provide a `roles`
array; the manager normalizes both forms and writes a canonical `roles` claim while
retaining `role` for backward compatibility:

```cfml
var tokens = tokenManager.issue( {
    id    : 101,
    roles : [ "admin", "finance" ]
} );
```

Simple checks return booleans:

```cfml
tokenManager.hasRole( tokens.accessToken, "admin" );
tokenManager.hasAnyRole( tokens.accessToken, [ "admin", "manager" ] );
tokenManager.hasAllRoles( tokens.accessToken, [ "admin", "finance" ] );
```

For protected handlers, `authorize()` validates the access token and returns its
trusted claims when the role requirement succeeds. It throws
`cftokenmanager.InsufficientRole` when the token is valid but lacks the required
role, allowing the application to return HTTP 403. Invalid or expired tokens still
produce the normal authentication failures and should result in HTTP 401.

```cfml
var claims = tokenManager.authorize( accessToken, [ "admin", "finance" ], "all" );
```

Use `diagnoseAuthorization()` when a handler needs a non-throwing result:

```cfml
var result = tokenManager.diagnoseAuthorization( accessToken, "admin" );
// { valid : true, authorized : false, code : "INSUFFICIENT_ROLE", message : "..." }
```

Roles are signed claims, not encrypted values. The application should derive them
from its trusted user/account record when issuing tokens. Role changes do not affect
already-issued tokens until they expire or the application adds revocation/version
checks.

### Verify + decode (protected route)

```cfml
if ( tokenManager.verify( accessToken ) ) {           // boolean, type defaults to "access"
    var claims = tokenManager.decode( accessToken );  // { sub, role, type, iat, exp, iss }
}
```

### Refresh (access token expired)

```cfml
var fresh = tokenManager.refresh( refreshToken );
// { "accessToken" : "<new access jwt>" }
```

### Precise error handling

`verify()` is a simple boolean. When you need to tell the client *why* a token was
rejected, use `diagnose()` (non-throwing) or `validate()` (throws typed exceptions):

```cfml
var result = tokenManager.diagnose( token );  // expects an access token
// { valid : false, code : "TOKEN_EXPIRED", message : "..." }
```

| code                  | meaning                                         |
| --------------------- | ----------------------------------------------- |
| `VALID`               | token is authentic, unexpired and correct type  |
| `MISSING_TOKEN`       | empty / no token supplied                        |
| `MALFORMED_TOKEN`     | not a 3-segment JWT or body is unparseable       |
| `INVALID_SIGNATURE`   | signature does not match the secret (tampered)   |
| `TOKEN_EXPIRED`       | `exp` claim is in the past                       |
| `INVALID_TOKEN_TYPE`  | e.g. a refresh token used on an access endpoint  |

The matching thrown exception types are `cftokenmanager.MalformedToken`,
`cftokenmanager.InvalidSignature`, `cftokenmanager.ExpiredToken` and
`cftokenmanager.InvalidTokenType`.

## Configuration

Override defaults from the host app's `config/Coldbox.cfc`:

```cfml
moduleSettings = {
    "cf-token-manager" : {
        secret             : getSystemSetting( "TOKEN_SECRET", "change-me" ),
        algorithm          : "HS512",   // HS256 | HS384 | HS512
        accessTokenExpiry  : 900,       // seconds (15 min)
        refreshTokenExpiry : 2592000,   // seconds (30 days)
        issuer             : "my-app"
    }
};
```

| setting              | default                                   |
| -------------------- | ----------------------------------------- |
| `secret`             | `cf-token-manager-default-secret-change-me` |
| `algorithm`          | `HS512`                                   |
| `accessTokenExpiry`  | `900` (15 minutes)                        |
| `refreshTokenExpiry` | `2592000` (30 days)                       |
| `issuer`             | `cf-token-manager`                        |

## Engine support

Signing uses the JVM `javax.crypto.Mac` / `SecretKeySpec` classes, so behaviour is
identical on Adobe ColdFusion, BoxLang and Lucee.

## Testing

Install the development dependencies, start a local CommandBox server, and run the
TestBox suite:

```bash
box install
box server start
box run-script test
```

The suite is located under `tests/specs/unit/TokenManagerSpec.cfc` and covers token
issuance, verification, refresh, diagnostics, role checks, and authorization.

## License

MIT
