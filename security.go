package oauth

import (
	"crypto/rc4"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
)

type TokenSecureFormatter interface {
	CryptToken(source []byte) ([]byte, error)
	DecryptToken(source []byte) ([]byte, error)
}

type TokenProvider struct {
	secureFormatter TokenSecureFormatter
}

func NewTokenProvider(formatter TokenSecureFormatter) *TokenProvider {
	return &TokenProvider{secureFormatter: formatter}
}

func (tp *TokenProvider) CryptToken(t *Token) (token string, err error) {
	bToken, err := json.Marshal(t)
	if err != nil {
		return "", err
	}
	return tp.crypt(bToken)
}

func (tp *TokenProvider) CryptRefreshToken(t *RefreshToken) (token string, err error) {
	bToken, err := json.Marshal(t)
	if err != nil {
		return "", err
	}
	return tp.crypt(bToken)
}

func (tp *TokenProvider) DecryptToken(token string) (t *Token, err error) {
	bToken, err := tp.decrypt(token)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(bToken, &t)
	if err != nil {
		return nil, err
	}
	return t, nil
}

func (tp *TokenProvider) DecryptRefreshTokens(refreshToken string) (refresh *RefreshToken, err error) {
	bRefresh, err := tp.decrypt(refreshToken)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(bRefresh, &refresh)
	if err != nil {
		return nil, err
	}
	return refresh, nil
}

func (tp *TokenProvider) crypt(token []byte) (string, error) {
	ctoken, err := tp.secureFormatter.CryptToken(token)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(ctoken), nil
}

func (tp *TokenProvider) decrypt(token string) ([]byte, error) {
	b, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		return nil, err
	}
	return tp.secureFormatter.DecryptToken(b)
}

type RC4TokenSecureFormatter struct {
	key    []byte
	cipher *rc4.Cipher
}

func NewRC4TokenSecurityProvider(key []byte) *RC4TokenSecureFormatter {
	var sc = &RC4TokenSecureFormatter{key: key}
	return sc
}

func (sc *RC4TokenSecureFormatter) CryptToken(source []byte) ([]byte, error) {
	dest := make([]byte, len(source))
	cipher, err := rc4.NewCipher(sc.key)
	if err != nil {
		return nil, err
	}
	cipher.XORKeyStream(dest, source)
	return dest, nil
}

func (sc *RC4TokenSecureFormatter) DecryptToken(source []byte) ([]byte, error) {
	dest := make([]byte, len(source))
	cipher, err := rc4.NewCipher(sc.key)
	if err != nil {
		panic(err)
	}
	cipher.XORKeyStream(dest, source)
	return dest, nil
}

type SHA256RC4TokenSecureFormatter struct {
	key    []byte
	cipher *rc4.Cipher
}

func NewSHA256RC4TokenSecurityProvider(key []byte) *SHA256RC4TokenSecureFormatter {
	var sc = &SHA256RC4TokenSecureFormatter{key: key}
	return sc
}

func (sc *SHA256RC4TokenSecureFormatter) CryptToken(source []byte) ([]byte, error) {
	hasher := sha256.New()
	hasher.Write(source)
	hash := hasher.Sum(nil)
	newSource := append(hash, source...)
	dest := make([]byte, len(newSource))
	cipher, err := rc4.NewCipher(sc.key)
	if err != nil {
		return nil, err
	}
	cipher.XORKeyStream(dest, newSource)
	return dest, nil
}

func (sc *SHA256RC4TokenSecureFormatter) DecryptToken(source []byte) ([]byte, error) {
	if len(source) < 32 {
		return nil, errors.New("Invalid token")
	}
	dest := make([]byte, len(source))
	cipher, err := rc4.NewCipher(sc.key)
	if err != nil {
		return nil, err
	}
	cipher.XORKeyStream(dest, source)
	hasher := sha256.New()
	hasher.Write(dest[32:])
	hash := hasher.Sum(nil)
	for i, b := range hash {
		if b != dest[i] {
			return nil, errors.New("Invalid token")
		}
	}
	return dest[32:], nil
}
