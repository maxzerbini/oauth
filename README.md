# oauth
OAuth 2.0 Authorization Server &amp; Authorization Middleware for Gin-Gonic

This library offer an OAuth 2.0 Authorization Server based on Gin-Gonic and a Resource Server Authorization Middleware for Gin-Gonic.

## Authorization Server
The Authorization Server is implemented by the struct _OAuthBearerServer_ that manages two grant type of authorizations. This Authorization Server is made to provide authorization token usable for consumimg resource's API. 

### Password grant type
_OAuthBearerServer_ supports password grant type allowing the token generation fo username / password credentials.

### Client Credentials grant type
_OAuthBearerServer_ supports client_credentials grant type allowing the token generation fo client_id / client_secret credentials.

### Authorization Code and Implicit grant type
The grant types are currently not supported.

### Refresh token grant type
Authorization token can expire so client can regenerate token using the refresh_token grant type.

## Authorization Middleware 
This Gin-Gonic middleware intercepts the resource server calls authorizing only calls that contain a valid beared token.
