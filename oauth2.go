package signature

import (
	"errors"
	"fmt"
	"time"
)

type TokenOAuth2 struct {
	s *Signature
}

// NewTokenOAuth2 - creates a token in OAuth2 format
func NewTokenOAuth2(rawkey interface{}) (tokenOAuth2 *TokenOAuth2, err error) {

	tokenOAuth2 = new(TokenOAuth2)

	tokenOAuth2.s, err = New(rawkey)
	if nil != err {
		return nil, fmt.Errorf("newtokenoauth2: error creating signature -> %w", err)
	}

	now := time.Now().UTC()
	iat := now.Unix()
	tokenOAuth2.s.Set("iat", iat)                         // default issued at is NOW in UTC
	tokenOAuth2.s.Set("nbf", iat)                         // default usable is same as iat
	tokenOAuth2.s.Set("exp", now.Add(time.Minute).Unix()) // default expiry is 1 minute from now

	return
}

func (tokenOAuth2 *TokenOAuth2) Set(key string, value interface{}) {
	tokenOAuth2.s.Set(key, value)
}

func (tokenOAuth2 *TokenOAuth2) SetIssuer(iss string) {
	tokenOAuth2.Set("iss", iss)
}

func (tokenOAuth2 *TokenOAuth2) SetClientID(clientid string) {
	tokenOAuth2.Set("client_id", clientid)
}

// SetIssuedAt - set the issued at field, by default the not before will batch iat. if replacing nbf with a newer value, call SetNotBefore after this function
func (tokenOAuth2 *TokenOAuth2) SetIssuedAt(iat time.Time) {
	tokenOAuth2.Set("iat", iat.Unix())
	tokenOAuth2.Set("nbf", iat.Unix()) // by default always set the nbf to match as iat
}

func (tokenOAuth2 *TokenOAuth2) SetNotBefore(nbf time.Time) {
	tokenOAuth2.Set("nbf", nbf.Unix())
}

func (tokenOAuth2 *TokenOAuth2) SetExpiry(exp time.Duration) {
	tokenOAuth2.Set("exp", time.Now().Add(exp).Unix())
}

func (tokenOAuth2 *TokenOAuth2) SetAudience(aud string) {
	tokenOAuth2.Set("aud", aud)
}

func (tokenOAuth2 *TokenOAuth2) SetSubject(sub string) {
	tokenOAuth2.Set("sub", sub)
}

func (tokenOAuth2 *TokenOAuth2) SetTokenIdentifier(tokenid string) {
	tokenOAuth2.Set("jti", tokenid)
}

func (tokenOAuth2 *TokenOAuth2) SetScope(scope string) {
	tokenOAuth2.Set("scope", scope)
}

// Generate - generates a usable OAuth2 token, for verifying load the accompanying public key into Signature and use the Verify function
func (tokenOAuth2 *TokenOAuth2) Generate() (sig []byte, err error) {

	_, ok := tokenOAuth2.s.data["iss"]
	if !ok {
		return nil, errors.New("issuer is not set")
	}

	_, ok = tokenOAuth2.s.data["jti"]
	if !ok {
		return nil, errors.New("json token identifier is not set")
	}

	_, ok = tokenOAuth2.s.data["iat"]
	if !ok {
		return nil, errors.New("issued at is not set")
	}

	_, ok = tokenOAuth2.s.data["nbf"]
	if !ok {
		return nil, errors.New("not before is not set")
	}

	_, ok = tokenOAuth2.s.data["exp"]
	if !ok {
		return nil, errors.New("expiry is not set")
	}

	_, ok = tokenOAuth2.s.data["aud"]
	if !ok {
		return nil, errors.New("audience is not set")
	}

	_, ok = tokenOAuth2.s.data["sub"]
	if !ok {
		return nil, errors.New("subject is not set")
	}

	_, ok = tokenOAuth2.s.data["client_id"]
	if !ok {
		return nil, errors.New("client identifier is not set")
	}

	return tokenOAuth2.s.Generate()
}
