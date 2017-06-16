package oauth

import (
	"errors"
	"testing"
	"time"
)

var _sut *OAuthBearerServer

func init() {
	_sut = NewOAuthBearerServer(
		"mySecretKey-10101",
		time.Second*60,
		&TestUserVerifier{},
		nil)
}

func TestGenerateTokensByUsername(t *testing.T) {
	token, refresh, err := _sut.generateTokens("user111", "U")
	if err == nil {
		t.Logf("Token: %v", token)
		t.Logf("Refresh Token: %v", refresh)
	} else {
		t.Fatalf("Error %s", err.Error())
	}
}

func TestCryptTokens(t *testing.T) {
	token, refresh, err := _sut.generateTokens("user222", "U")
	if err == nil {
		t.Logf("Token: %v", token)
		t.Logf("Refresh Token: %v", refresh)
	} else {
		t.Fatalf("Error %s", err.Error())
	}
	resp, err := _sut.cryptTokens(token, refresh)
	if err == nil {
		t.Logf("Response: %v", resp)
	} else {
		t.Fatalf("Error %s", err.Error())
	}
}

func TestDecryptRefreshTokens(t *testing.T) {
	token, refresh, err := _sut.generateTokens("user333", "U")
	if err == nil {
		t.Logf("Token: %v", token)
		t.Logf("Refresh Token: %v", refresh)
	} else {
		t.Fatalf("Error %s", err.Error())
	}
	resp, err := _sut.cryptTokens(token, refresh)
	if err == nil {
		t.Logf("Response: %v", resp)
		t.Logf("Response Refresh Token: %v", resp.RefreshToken)
	} else {
		t.Fatalf("Error %s", err.Error())
	}
	refresh2, err := _sut.provider.DecryptRefreshTokens(resp.RefreshToken)
	if err == nil {
		t.Logf("Refresh Token Decrypted: %v", refresh2)
	} else {
		t.Fatalf("Error %s", err.Error())
	}
}

func TestGenerateToken4Password(t *testing.T) {
	code, resp := _sut.generateTokenResponse("password", "user111", "password111", "", "", "", "")
	if code != 200 {
		t.Fatalf("Error StatusCode = %d", code)
	}
	t.Logf("Token response: %v", resp)
}

func TestShouldFailGenerateToken4Password(t *testing.T) {
	code, _ := _sut.generateTokenResponse("password", "user111", "password4444", "", "", "", "")
	t.Logf("Server response: %v", code)
	if code != 401 {
		t.Fatalf("Error StatusCode = %d", code)
	}
}

func TestGenerateToken4ClientCredentials(t *testing.T) {
	code, resp := _sut.generateTokenResponse("client_credentials", "abcdef", "12345", "", "", "", "")
	if code != 200 {
		t.Fatalf("Error StatusCode = %d", code)
	}
	t.Logf("Token response: %v", resp)
}

func TestRefreshToken4ClientCredentials(t *testing.T) {
	code, resp := _sut.generateTokenResponse("client_credentials", "abcdef", "12345", "", "", "", "")
	if code != 200 {
		t.Fatalf("Error StatusCode = %d", code)
	}
	t.Logf("Token Response: %v", resp)
	code2, resp2 := _sut.generateTokenResponse("refresh_token", "", "", resp.(*TokenResponse).RefreshToken, "", "", "")
	if code2 != 200 {
		t.Fatalf("Error StatusCode = %d", code2)
	}
	t.Logf("New Token Response: %v", resp2)
}

// TestUserVerifier provides user credentials verifier for testing.
type TestUserVerifier struct {
}

// Validate username and password returning an error if the user credentials are wrong
func (*TestUserVerifier) ValidateUser(username, password, scope string) error {
	if username == "user111" && password == "password111" {
		return nil
	} else if username == "user222" && password == "password222" {
		return nil
	} else if username == "user333" && password == "password333" {
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
func (*TestUserVerifier) AddClaims(credential, tokenID, tokenType, scope string) (map[string]string, error) {
	claims := make(map[string]string)
	claims["customerId"] = "1001"
	claims["customerData"] = `{"OrderDate":"2016-12-14","OrderId":"9999"}`
	return claims, nil
}

// Optionally store the token Id generated for the user
func (*TestUserVerifier) StoreTokenId(credential, tokenID, refreshTokenID, tokenType string) error {
	return nil
}

// Provide additional information to the token response
func (*TestUserVerifier) AddProperties(credential, tokenID, tokenType string) (map[string]string, error) {
	props := make(map[string]string)
	props["customerName"] = "Gopher"
	return props, nil
}

// Validate token Id
func (*TestUserVerifier) ValidateTokenId(credential, tokenID, refreshTokenID, tokenType string) error {
	return nil
}
