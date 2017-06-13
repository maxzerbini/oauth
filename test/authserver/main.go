package main

import (
	"errors"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/maxzerbini/oauth"
	cors "gopkg.in/gin-contrib/cors.v1"
)

/*
   Authorization Server Example

    Generate Token using username & password

    	POST http://localhost:3000/token
		User-Agent: Fiddler
		Host: localhost:3000
		Content-Length: 50
		Content-Type: application/x-www-form-urlencoded

		grant_type=password&username=user01&password=12345

	Generate Token using clientId & secret

    	POST http://localhost:3000/auth
		User-Agent: Fiddler
		Host: localhost:3000
		Content-Length: 66
		Content-Type: application/x-www-form-urlencoded

		grant_type=client_credentials&client_id=abcdef&client_secret=12345

	Refresh Token

		POST http://localhost:3000/token
		User-Agent: Fiddler
		Host: localhost:3000
		Content-Length: 50
		Content-Type: application/x-www-form-urlencoded

		grant_type=refresh_token&refresh_token={the refresh_token obtained in the previous response}

*/
func main() {
	router := gin.New()
	router.Use(gin.Recovery())
	router.Use(gin.Logger())
	router.Use(cors.Default()) // enable Cross-Origin Resource Sharing
	gin.SetMode(gin.DebugMode)
	registerAPI(router)
	router.Run(":3000")
}

func registerAPI(router *gin.Engine) {
	s := oauth.NewOAuthBearerServer(
		"mySecretKey-10101",
		time.Second*120,
		&TestUserVerifier{},
		nil)
	router.POST("/token", s.UserCredentials)
	router.POST("/auth", s.ClientCredentials)
}

// TestUserVerifier provides user credentials verifier for testing.
type TestUserVerifier struct {
}

// Validate username and password returning an error if the user credentials are wrong
func (*TestUserVerifier) ValidateUser(username, password, scope string) error {
	if username == "user01" && password == "12345" {
		return nil
	} else {
		return errors.New("Wrong user")
	}
}

// Validate clientId and secret returning an error if the client credentials are wrong
func (*TestUserVerifier) ValidateClient(clientId, clientSecret, scope string) error {
	if clientId == "abcdef" && clientSecret == "12345" {
		return nil
	} else {
		return errors.New("Wrong client")
	}
}

// Provide additional claims to the token
func (*TestUserVerifier) AddClaims(credential, tokenId, tokenType string) (map[string]string, error) {
	claims := make(map[string]string)
	claims["customerId"] = "1001"
	claims["customerData"] = `{"OrderDate":"2016-12-14","OrderId":"9999"}`
	return claims, nil
}

// Optionally store the token Id generated for the user
func (*TestUserVerifier) StoreTokenId(credential, tokenId, refreshTokenID, tokenType string) error {
	return nil
}

// Provide additional information to the token response
func (*TestUserVerifier) AddProperties(credential, tokenId, tokenType string) (map[string]string, error) {
	props := make(map[string]string)
	props["customerName"] = "Gopher"
	return props, nil
}

// Validate token Id
func (*TestUserVerifier) ValidateTokenId(credential, tokenId, refreshTokenID, tokenType string) error {
	return nil
}
