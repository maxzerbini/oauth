package oauth

import (
	"testing"
)

var _sutRC4, _sutSHA256 *TokenProvider

func init() {
	_sutRC4 = NewTokenProvider(NewRC4TokenSecurityProvider([]byte("testkey")))
	_sutSHA256 = NewTokenProvider(NewSHA256RC4TokenSecurityProvider([]byte("testkey")))
}

func TestCrypt(t *testing.T) {
	var token string = `{"CreationDate":"2016-12-14","Expiration":"1000"}`
	result, err := _sutRC4.crypt([]byte(token))
	if err != nil {
		t.Fatalf("Error %s", err.Error())
	}
	t.Logf("Base64 Token : %v", result)
}

func TestDecrypt(t *testing.T) {
	var token string = `{"CreationDate":"2016-12-14","Expiration":"1000"}`
	var bToken []byte = []byte(token)
	t.Logf("Base64 Token : %v", bToken)
	result, err := _sutRC4.crypt([]byte(token))
	if err != nil {
		t.Fatalf("Error %s", err.Error())
	}
	t.Logf("Base64 Token : %v", result)
	decrypt, err := _sutRC4.decrypt(result)
	if err != nil {
		t.Fatalf("Error %s", err.Error())
	}
	t.Logf("Base64 Token Decrypted: %v", decrypt)
	t.Logf("Base64 Token Decrypted: %s", decrypt)
	for i := range bToken {
		if bToken[i] != decrypt[i] {
			t.Fatalf("Error in decryption")
		}
	}
}

func TestCryptSHA256(t *testing.T) {
	var token string = `{"CreationDate":"2016-12-14","Expiration":"1000"}`
	result, err := _sutSHA256.crypt([]byte(token))
	if err != nil {
		t.Fatalf("Error %s", err.Error())
	}
	t.Logf("Base64 Token : %v", result)
}

func TestDecryptSHA256(t *testing.T) {
	var token string = `{"CreationDate":"2016-12-14","Expiration":"1000"}`
	var bToken []byte = []byte(token)
	t.Logf("Base64 Token : %v", bToken)
	result, err := _sutSHA256.crypt([]byte(token))
	if err != nil {
		t.Fatalf("Error %s", err.Error())
	}
	t.Logf("Base64 Token : %v", result)
	decrypt, err := _sutSHA256.decrypt(result)
	if err != nil {
		t.Fatalf("Error %s", err.Error())
	}
	t.Logf("Base64 Token Decrypted: %v", decrypt)
	t.Logf("Base64 Token Decrypted: %s", decrypt)
	for i := range bToken {
		if bToken[i] != decrypt[i] {
			t.Fatalf("Error in decryption")
		}
	}
}

func TestDecryptSHA256_LongKey(t *testing.T) {
	sutSHA256 := NewTokenProvider(NewSHA256RC4TokenSecurityProvider([]byte("518baffa-b290-4c01-a150-1980f5b06a01")))
	var token string = `{"CreationDate":"2016-12-14","Expiration":"1000"}`
	var bToken []byte = []byte(token)
	t.Logf("Base64 Token : %v", bToken)
	result, err := sutSHA256.crypt([]byte(token))
	if err != nil {
		t.Fatalf("Error %s", err.Error())
	}
	t.Logf("Base64 Token : %v", result)
	decrypt, err := sutSHA256.decrypt(result)
	if err != nil {
		t.Fatalf("Error %s", err.Error())
	}
	t.Logf("Base64 Token Decrypted: %v", decrypt)
	t.Logf("Base64 Token Decrypted: %s", decrypt)
	for i := range bToken {
		if bToken[i] != decrypt[i] {
			t.Fatalf("Error in decryption")
		}
	}
}
