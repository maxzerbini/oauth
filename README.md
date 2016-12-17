# oauth
OAuth 2.0 Authorization Server &amp; Authorization Middleware for Gin-Gonic

This library offers an OAuth 2.0 Authorization Server based on Gin-Gonic and an Authorization Gin-Gonic Middleware for Resource Server.

## Authorization Server
The Authorization Server is implemented by the struct _OAuthBearerServer_ that manages two grant type of authorizations. This Authorization Server is made to provide authorization token usable for consumimg resource's API. 

### Password grant type
_OAuthBearerServer_ supports password grant type allowing the token generation for username / password credentials.

### Client Credentials grant type
_OAuthBearerServer_ supports client_credentials grant type allowing the token generation for client_id / client_secret credentials.

### Authorization Code and Implicit grant type
These grant types are currently not supported.

### Refresh token grant type
If authorization token will expire, client can regenerate token using the refresh_token grant type.

## Authorization Middleware 
This Gin-Gonic middleware _BearerAuthentication_ intercepts the resource server calls authorizing only calls that contain a valid bearer token.
