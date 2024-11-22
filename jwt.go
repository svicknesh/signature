package signature

import (
	"errors"
	"fmt"
	"time"
)

type TokenJWT struct {
	s *Signature
}

// NewTokenJWT - creates a token in JWT format
func NewTokenJWT(rawkey interface{}) (tokenJWT *TokenJWT, err error) {

	tokenJWT = new(TokenJWT)

	tokenJWT.s, err = FromRaw(rawkey)
	if nil != err {
		return nil, fmt.Errorf("newtokenoauth2: error creating signature -> %w", err)
	}

	now := time.Now().UTC()
	iat := now.Unix()
	tokenJWT.s.Set("iat", iat)                         // default issued at is NOW in UTC
	tokenJWT.s.Set("nbf", iat)                         // default usable is same as iat
	tokenJWT.s.Set("exp", now.Add(time.Minute).Unix()) // default expiry is 1 minute from now

	return
}

func (tokenJWT *TokenJWT) Set(key string, value interface{}) {
	tokenJWT.s.Set(key, value)
}

func (tokenJWT *TokenJWT) SetIssuer(iss string) {
	tokenJWT.Set("iss", iss)
}

// SetIssuedAt - set the issued at field, by default the not before will batch iat. if replacing nbf with a newer value, call SetNotBefore after this function
func (tokenJWT *TokenJWT) SetIssuedAt(iat time.Time) {
	tokenJWT.Set("iat", iat.Unix())
	tokenJWT.Set("nbf", iat.Unix()) // by default always set the nbf to match as iat
}

func (tokenJWT *TokenJWT) SetNotBefore(nbf time.Time) {
	tokenJWT.Set("nbf", nbf.Unix())
}

func (tokenJWT *TokenJWT) SetExpiry(exp time.Duration) {
	tokenJWT.Set("exp", time.Now().Add(exp).Unix())
}

func (tokenJWT *TokenJWT) SetAudience(aud string) {
	tokenJWT.Set("aud", aud)
}

func (tokenJWT *TokenJWT) SetSubject(sub string) {
	tokenJWT.Set("sub", sub)
}

func (tokenJWT *TokenJWT) SetTokenIdentifier(tokenid string) {
	tokenJWT.Set("jti", tokenid)
}

func (tokenJWT *TokenJWT) SetScope(scope string) {
	tokenJWT.Set("scope", scope)
}

// Generate - generates a usable JWT token, for verifying load the accompanying public key into Signature and use the Verify function
func (tokenJWT *TokenJWT) Generate() (sig []byte, err error) {

	_, ok := tokenJWT.s.data["iss"]
	if !ok {
		return nil, errors.New("issuer is not set")
	}

	_, ok = tokenJWT.s.data["jti"]
	if !ok {
		return nil, errors.New("json token identifier is not set")
	}

	_, ok = tokenJWT.s.data["iat"]
	if !ok {
		return nil, errors.New("issued at is not set")
	}

	_, ok = tokenJWT.s.data["nbf"]
	if !ok {
		return nil, errors.New("not before is not set")
	}

	_, ok = tokenJWT.s.data["exp"]
	if !ok {
		return nil, errors.New("expiry is not set")
	}

	_, ok = tokenJWT.s.data["aud"]
	if !ok {
		return nil, errors.New("audience is not set")
	}

	_, ok = tokenJWT.s.data["sub"]
	if !ok {
		return nil, errors.New("subject is not set")
	}

	return tokenJWT.s.Generate()
}
