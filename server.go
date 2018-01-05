package oauth

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/satori/go.uuid"
)

const (
	TOKEN_TYPE = "Bearer"
)

type Any interface{}

// CredentialsVerifier defines the interface of the user and client credentials verifier.
type CredentialsVerifier interface {
	// Validate username and password returning an error if the user credentials are wrong
	ValidateUser(username, password, scope string, req *http.Request) error
	// Validate clientId and secret returning an error if the client credentials are wrong
	ValidateClient(clientID, clientSecret, scope string, req *http.Request) error
	// Provide additional claims to the token
	AddClaims(credential, tokenID, tokenType, scope string) (map[string]string, error)
	// Optionally store the tokenID generated for the user
	StoreTokenId(credential, tokenID, refreshTokenID, tokenType string) error
	// Provide additional information to the authorization server response
	AddProperties(credential, tokenID, tokenType string) (map[string]string, error)
	// Optionally validate previously stored tokenID during refresh request
	ValidateTokenId(credential, tokenID, refreshTokenID, tokenType string) error
}

// AuthorizationCodeVerifier defines the interface of the Authorization Code verifier
type AuthorizationCodeVerifier interface {
	// ValidateCode checks the authorization code and returns the user credential
	ValidateCode(clientID, clientSecret, code, redirectURI string, req *http.Request) (string, error)
}

// OAuthBearerServer is the OAuth 2 Bearer Server implementation.
type OAuthBearerServer struct {
	secretKey string
	TokenTTL  time.Duration
	verifier  CredentialsVerifier
	provider  *TokenProvider
}

// NewOAuthBearerServer creates new OAuth 2 Bearer Server
func NewOAuthBearerServer(secretKey string,
	ttl time.Duration,
	verifier CredentialsVerifier,
	formatter TokenSecureFormatter) *OAuthBearerServer {
	if formatter == nil {
		formatter = NewSHA256RC4TokenSecurityProvider([]byte(secretKey))
	}
	obs := &OAuthBearerServer{
		secretKey: secretKey,
		TokenTTL:  ttl,
		verifier:  verifier,
		provider:  NewTokenProvider(formatter)}
	return obs
}

// UserCredentials manages password grant type requests
func (s *OAuthBearerServer) UserCredentials(ctx *gin.Context) {
	grantType := ctx.PostForm("grant_type")
	// grant_type password variables
	username := ctx.PostForm("username")
	password := ctx.PostForm("password")
	scope := ctx.PostForm("scope")
	if username == "" || password == "" {
		// get username and password from basic authorization header
		var err error
		username, password, err = GetBasicAuthentication(ctx)
		if err != nil {
			ctx.JSON(http.StatusUnauthorized, "Not authorized")
			return
		}
	}
	// grant_type refresh_token
	refreshToken := ctx.PostForm("refresh_token")
	code, resp := s.generateTokenResponse(grantType, username, password, refreshToken, scope, "", "", ctx.Request)
	ctx.JSON(code, resp)
}

// ClientCredentials manages client credentials grant type requests
func (s *OAuthBearerServer) ClientCredentials(ctx *gin.Context) {
	grantType := ctx.PostForm("grant_type")
	// grant_type client_credentials variables
	clientId := ctx.PostForm("client_id")
	clientSecret := ctx.PostForm("client_secret")
	if clientId == "" || clientSecret == "" {
		// get clientId and secret from basic authorization header
		var err error
		clientId, clientSecret, err = GetBasicAuthentication(ctx)
		if err != nil {
			ctx.JSON(http.StatusUnauthorized, "Not authorized")
			return
		}
	}
	scope := ctx.PostForm("scope")
	// grant_type refresh_token
	refreshToken := ctx.PostForm("refresh_token")
	code, resp := s.generateTokenResponse(grantType, clientId, clientSecret, refreshToken, scope, "", "", ctx.Request)
	ctx.JSON(code, resp)
}

// AuthorizationCode manages authorization code grant type requests for the phase two of the authorization process
func (s *OAuthBearerServer) AuthorizationCode(ctx *gin.Context) {
	grantType := ctx.PostForm("grant_type")
	// grant_type client_credentials variables
	clientId := ctx.PostForm("client_id")
	clientSecret := ctx.PostForm("client_secret") // not mandatory
	code := ctx.PostForm("code")
	redirectURI := ctx.PostForm("redirect_uri") // not mandatory
	scope := ctx.PostForm("scope")              // not mandatory
	if clientId == "" {
		// get clientId and secret from basic authorization header
		var err error
		clientId, clientSecret, err = GetBasicAuthentication(ctx)
		if err != nil {
			ctx.JSON(http.StatusUnauthorized, "Not authorized")
			return
		}
	}
	status, resp := s.generateTokenResponse(grantType, clientId, clientSecret, "", scope, code, redirectURI, ctx.Request)
	ctx.JSON(status, resp)
}

// Generate token response
func (s *OAuthBearerServer) generateTokenResponse(grantType, credential, secret, refreshToken, scope, code, redirectURI string, req *http.Request) (int, Any) {
	// check grant_Type
	if grantType == "password" {
		err := s.verifier.ValidateUser(credential, secret, scope, req)
		if err == nil {
			token, refresh, err := s.generateTokens(credential, "U", scope)
			if err == nil {
				// Store token id
				err = s.verifier.StoreTokenId(credential, token.Id, refresh.RefreshTokenId, token.TokenType)
				if err != nil {
					return http.StatusInternalServerError, "Storing Token Id failed"
				}
				resp, err := s.cryptTokens(token, refresh)
				if err == nil {
					return http.StatusOK, resp
				} else {
					return http.StatusInternalServerError, "Token generation failed, check security provider"
				}
			} else {
				return http.StatusInternalServerError, "Token generation failed, check claims"
			}

		} else {
			//not autorized
			return http.StatusUnauthorized, "Not authorized"
		}
	} else if grantType == "client_credentials" {
		err := s.verifier.ValidateClient(credential, secret, scope, req)
		if err == nil {
			token, refresh, err := s.generateTokens(credential, "C", scope)
			if err == nil {
				// Store token id
				err = s.verifier.StoreTokenId(credential, token.Id, refresh.RefreshTokenId, token.TokenType)
				if err != nil {
					return http.StatusInternalServerError, "Storing Token Id failed"
				}
				resp, err := s.cryptTokens(token, refresh)
				if err == nil {
					return http.StatusOK, resp
				} else {
					return http.StatusInternalServerError, "Token generation failed, check security provider"
				}
			} else {
				return http.StatusInternalServerError, "Token generation failed, check claims"
			}
		} else {
			//not autorized
			return http.StatusUnauthorized, "Not authorized"
		}
	} else if grantType == "authorization_code" {
		if codeVerifier, ok := s.verifier.(AuthorizationCodeVerifier); ok {
			user, err := codeVerifier.ValidateCode(credential, secret, code, redirectURI, req)
			if err == nil {
				token, refresh, err := s.generateTokens(user, "A", scope)
				if err == nil {
					// Store token id
					err = s.verifier.StoreTokenId(user, token.Id, refresh.RefreshTokenId, token.TokenType)
					if err != nil {
						return http.StatusInternalServerError, "Storing Token Id failed"
					}
					resp, err := s.cryptTokens(token, refresh)
					if err == nil {
						return http.StatusOK, resp
					} else {
						return http.StatusInternalServerError, "Token generation failed, check security provider"
					}
				} else {
					return http.StatusInternalServerError, "Token generation failed, check claims"
				}
			} else {
				//not autorized
				return http.StatusUnauthorized, "Not authorized"
			}
		} else {
			//not autorized
			return http.StatusUnauthorized, "Not authorized, grant type not supported"
		}
	} else if grantType == "refresh_token" {
		// refresh token
		refresh, err := s.provider.DecryptRefreshTokens(refreshToken)
		if err == nil {
			err = s.verifier.ValidateTokenId(refresh.Credential, refresh.TokenId, refresh.RefreshTokenId, refresh.TokenType)
			if err == nil {
				// generate new token
				token, refresh, err := s.generateTokens(refresh.Credential, refresh.TokenType, refresh.Scope)
				if err == nil {
					// Store token id
					err = s.verifier.StoreTokenId(refresh.Credential, token.Id, refresh.RefreshTokenId, token.TokenType)
					if err != nil {
						return http.StatusInternalServerError, "Storing Token Id failed"
					}
					resp, err := s.cryptTokens(token, refresh)
					if err == nil {
						return http.StatusOK, resp
					} else {
						return http.StatusInternalServerError, "Token generation failed"
					}
				} else {
					return http.StatusInternalServerError, "Token generation failed"
				}
			} else {
				//not autorized invalid token Id
				return http.StatusUnauthorized, "Not authorized invalid token"
			}
		} else {
			//not autorized
			return http.StatusUnauthorized, "Not authorized"
		}
	} else {
		// Invalid request
		return http.StatusBadRequest, "Invalid grant_type"
	}
}

func (s *OAuthBearerServer) generateTokens(username, tokenType, scope string) (token *Token, refresh *RefreshToken, err error) {
	token = &Token{Credential: username, ExperesIn: s.TokenTTL, CreationDate: time.Now().UTC(), TokenType: tokenType, Scope: scope}
	// generate token Id
	token.Id = uuid.Must(uuid.NewV4()).String()
	if s.verifier != nil {
		claims, err := s.verifier.AddClaims(username, token.Id, token.TokenType, token.Scope)
		if err == nil {
			token.Claims = claims
		} else {
			// claims error
			return nil, nil, err
		}
	}
	// create refresh token
	refresh = &RefreshToken{RefreshTokenId: uuid.Must(uuid.NewV4()).String(), TokenId: token.Id, CreationDate: time.Now().UTC(), Credential: username, TokenType: tokenType, Scope: scope}

	return token, refresh, nil
}

func (s *OAuthBearerServer) cryptTokens(token *Token, refresh *RefreshToken) (resp *TokenResponse, err error) {
	ctoken, err := s.provider.CryptToken(token)
	if err != nil {
		return nil, err
	}
	crefresh, err := s.provider.CryptRefreshToken(refresh)
	if err != nil {
		return nil, err
	}
	resp = &TokenResponse{Token: ctoken, RefreshToken: crefresh, TokenType: TOKEN_TYPE, ExperesIn: (int64)(s.TokenTTL / time.Second)}

	if s.verifier != nil {
		// add properties
		props, err := s.verifier.AddProperties(token.Credential, token.Id, token.TokenType)
		if err == nil {
			resp.Properties = props
		}
	}
	return resp, nil
}
