# oauth middleware
OAuth 2.0 Authorization Server &amp; Authorization Middleware for [Gin-Gonic](https://github.com/gin-gonic/gin)

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
This Gin-Gonic middleware _BearerAuthentication_ intercepts the resource server calls and authorizes only calls containing a valid bearer token.

## Token Formatter
Authorization Server crypts token using the Token Formatter and Authorization Middleware decrypts the token using the same Token Formatter.
Programmers can develope their Token Formatter implementing the interface _TokenSecureFormatter_. 
This library contains a default implementation of the formatter interface called _SHA256RC4TokenSecureFormatter_ based on the algorithms SHA256 and RC4.

## Authorization Server usage example
This snippet shows how to create an authorization server
```Go
func main() {
	router := gin.New()
	router.Use(gin.Recovery())
	router.Use(gin.Logger())

    s := oauth.NewOAuthBearerServer(
		"mySecretKey-10101",
		time.Second*120,
		&TestUserVerifier{},
		nil)
	router.POST("/token", s.UserCredentials)
	router.POST("/auth", s.ClientCredentials)
	
	router.Run(":9090")
}
```
See /test/authserver/main.go for the full example.

## Authorization Middleware usage example
This snippet shows how to use the middleware
```Go
    authorized := router.Group("/")
	// use the Bearer Athentication meddleware
	authorized.Use(oauth.Authorize("mySecretKey-10101", nil))

	authorized.GET("/customers", GetCustomers)
	authorized.GET("/customers/:id/orders", GetOrders)
```
See /test/resourceserver/main.go for the full example.

Note that the authorization server and the authorization middleware are both using the same token formatter and the same secret key for encryption/decryption.

## Reference
- [OAuth 2.0 RFC](https://tools.ietf.org/html/rfc6749)
- [OAuth 2.0 Bearer Token Usage RFC](https://tools.ietf.org/html/rfc6750)
