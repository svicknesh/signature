package signature

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/json"
	"fmt"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jws"
)

// Signature - structure for managing singing information
type Signature struct {
	privkey interface{}
	pubKey  interface{}
	alg     jwa.SignatureAlgorithm
	//token   jwt.Token
	data map[string]interface{}

	// helper variables useful in other parts of this library
	isPrivateKey bool
	isPublicKey  bool
}

// New - creates new instance of signature for generation or verification
func New(key interface{}) (s *Signature, err error) {

	s = new(Signature)

	// get the type of key issued
	switch key.(type) {
	case *ecdsa.PrivateKey:
		s.isPrivateKey = true
		s.isPublicKey = true

		priv := key.(*ecdsa.PrivateKey)
		s.privkey = key
		s.pubKey = &priv.PublicKey

		switch priv.PublicKey.Curve.Params().Name {
		case "P-256":
			s.alg = jwa.ES256
		case "P-384":
			s.alg = jwa.ES384
		case "P-512":
			s.alg = jwa.ES512
		}

	case ecdsa.PrivateKey:
		s.isPrivateKey = true
		s.isPublicKey = true

		priv := key.(ecdsa.PrivateKey)
		s.privkey = &priv
		s.pubKey = &priv.PublicKey

		switch priv.PublicKey.Curve.Params().Name {
		case "P-256":
			s.alg = jwa.ES256
		case "P-384":
			s.alg = jwa.ES384
		case "P-512":
			s.alg = jwa.ES512
		}

	case *ecdsa.PublicKey:
		s.isPublicKey = true

		s.pubKey = key

		switch key.(*ecdsa.PublicKey).Curve.Params().Name {
		case "P-256":
			s.alg = jwa.ES256
		case "P-384":
			s.alg = jwa.ES384
		case "P-512":
			s.alg = jwa.ES512
		}

	case ecdsa.PublicKey:
		s.isPublicKey = true

		pub := key.(ecdsa.PublicKey)

		s.pubKey = &pub

		switch pub.Curve.Params().Name {
		case "P-256":
			s.alg = jwa.ES256
		case "P-384":
			s.alg = jwa.ES384
		case "P-512":
			s.alg = jwa.ES512
		}

	case *rsa.PrivateKey:
		s.isPrivateKey = true
		s.isPublicKey = true

		s.privkey = key
		s.pubKey = &key.(*rsa.PrivateKey).PublicKey

		s.alg = jwa.RS256 // default signing algorithm for RSA

	case rsa.PrivateKey:
		s.isPrivateKey = true
		s.isPublicKey = true

		priv := key.(rsa.PrivateKey)
		s.privkey = &priv
		s.pubKey = &priv.PublicKey

		s.alg = jwa.RS256 // default signing algorithm for RSA

	case *rsa.PublicKey:
		s.isPublicKey = true

		s.pubKey = key

		s.alg = jwa.RS256 // default signing algorithm for RSA

	case rsa.PublicKey:
		s.isPublicKey = true

		pub := key.(rsa.PublicKey)
		s.pubKey = &pub

		s.alg = jwa.RS256 // default signing algorithm for RSA

	default:
		return nil, fmt.Errorf("signature new: unsupported key type %T", key)
	}

	//s.token = jwt.New()
	s.data = make(map[string]interface{})

	return
}

// Set - sets a key for signing
func (s *Signature) Set(key string, value interface{}) {
	s.data[key] = value
}

// Generate - generates a signature
func (s *Signature) Generate() (signed []byte, err error) {

	if !s.isPrivateKey {
		return nil, fmt.Errorf("signature generate: no private key for signing data")
	}

	bytes, _ := json.Marshal(s.data)

	signed, err = jws.Sign(bytes, s.alg, s.privkey) // a JWS is the basis for all other types such as generic JWT, Oauth2, etc
	if nil != err {
		return nil, fmt.Errorf("signature generate: %w", err)
	}

	return
}

// Verify - verifies a signature
func (s *Signature) Verify(signed []byte) (payload []byte, err error) {

	if !s.isPublicKey {
		return nil, fmt.Errorf("signature generate: no public key for verifying data")
	}

	payload, err = jws.Verify(signed, s.alg, s.pubKey) // we just need to know if the signature is valid, payload checking will be done by the calling app

	return
}
