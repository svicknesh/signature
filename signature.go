package signature

import (
	"encoding/json"
	"fmt"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/svicknesh/key/v2/shared"
)

type Key shared.Key

/*
type SigAlgorithm jwa.SignatureAlgorithm

const (
	SIGES256       = jwa.ES256
	SIGES256K      = jwa.ES256K
	SIGES384       = jwa.ES384
	SIGES512       = jwa.ES512
	SIGEdDSA       = jwa.EdDSA
	SIGHS256       = jwa.HS256
	SIGHS384       = jwa.HS384
	SIGHS512       = jwa.HS512
	SIGNoSignature = jwa.NoSignature
	SIGPS256       = jwa.PS256
	SIGPS384       = jwa.PS384
	SIGPS512       = jwa.PS512
	SIGRS256       = jwa.RS256
	SIGRS384       = jwa.RS384
	SIGRS512       = jwa.RS512
)
*/

// Signature - structure for managing singing information
type Signature struct {
	k   Key
	alg jwa.SignatureAlgorithm
	//token   jwt.Token
	data map[string]interface{}
}

/*
// New - creates new instance of signature for generation or verification
func New(keyBytes []byte) (s *Signature, err error) {

	s = new(Signature)

	s.k, err = key.NewFromRawKey(rawkey)
	if nil != err {
		return nil, fmt.Errorf("new signature: error parsing raw key -> %w", err)
	}

	switch s.k.KeyType() {
	case shared.ECDSA256:
		s.alg = jwa.ES256()
	case shared.ECDSA384:
		s.alg = jwa.ES384()
	case shared.ECDSA521:
		s.alg = jwa.ES512()
	case shared.ED25519:
		s.alg = jwa.EdDSA()
	case shared.RSA2048:
		s.alg = jwa.RS256()
	case shared.RSA4096:
		s.alg = jwa.RS384()
	case shared.RSA8192:
		s.alg = jwa.RS512()
	}

	//s.token = jwt.New()
	s.data = make(map[string]interface{})

	return
}
*/

// initData - initializes the map for storing type/value pairs
func (s *Signature) initData() {
	s.data = make(map[string]interface{})
}

// setAlg - sets the keys signing algorithm
func (s *Signature) setAlg() {
	switch s.k.KeyType() {
	case shared.ECDSA256:
		s.alg = jwa.ES256()
	case shared.ECDSA384:
		s.alg = jwa.ES384()
	case shared.ECDSA521:
		s.alg = jwa.ES512()
	case shared.ED25519:
		s.alg = jwa.EdDSA()
	case shared.RSA2048:
		s.alg = jwa.RS256()
	case shared.RSA4096:
		s.alg = jwa.RS384()
	case shared.RSA8192:
		s.alg = jwa.RS512()
	}
}

// Set - sets a type/value pair for signing
func (s *Signature) Set(t string, value interface{}) {
	s.data[t] = value
}

// Generate - generates a signature
func (s *Signature) Generate() (signed []byte, err error) {

	if !s.k.IsPrivateKey() {
		return nil, fmt.Errorf("signature generate: no private key for signing data")
	}

	bytes, err := json.Marshal(s.data)
	if nil != err {
		return nil, fmt.Errorf("signature generate: marshal -> %w", err)
	}

	signed, err = jws.Sign(bytes, jws.WithKey(s.alg, s.k.PrivateKeyInstance())) // a JWS is the basis for all other types such as generic JWT, Oauth2, etc
	if nil != err {
		return nil, fmt.Errorf("signature generate: %w", err)
	}

	return
}

// Verify - verifies a signature
func (s *Signature) Verify(signed []byte) (payload []byte, err error) {

	if !s.k.IsPublicKey() {
		return nil, fmt.Errorf("signature generate: no public key for verifying data")
	}

	payload, err = jws.Verify(signed, jws.WithKey(s.alg, s.k.PublicKeyInstance())) // we just need to know if the signature is valid, payload checking will be done by the calling app

	return
}
