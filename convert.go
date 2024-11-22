package signature

import (
	"fmt"

	"github.com/svicknesh/key/v2"
)

// FromRaw - parses raw key into signature key
func FromRaw(raw interface{}) (s *Signature, err error) {

	s = new(Signature)

	s.k, err = key.NewFromRawKey(raw)
	if nil != err {
		return nil, fmt.Errorf("parseRaw: error parsing raw key -> %w", err)
	}
	//fmt.Println(s.k.String())

	s.setAlg()   // sets the signing algorithm
	s.initData() // inits the map for storing type/value pairs

	return
}

// FromJWK - parses JWK JSON encoded bytes into signature key
func FromJWK(jsonBytes []byte) (s *Signature, err error) {

	s = new(Signature)

	s.k, err = key.NewKeyFromBytes(jsonBytes)
	if nil != err {
		return nil, fmt.Errorf("parseJWK: error parsing JWK -> %w", err)
	}
	//fmt.Println(s.k.String())

	s.setAlg()   // sets the signing algorithm
	s.initData() // inits the map for storing type/value pairs

	/*
		var raw interface{}
		if j.IsPrivateKey() {
			raw = j.PrivateKeyInstance()
		} else if j.IsPublicKey() {
			raw = j.PublicKeyInstance()
		} else {
			return nil, fmt.Errorf("parseJWK: JWK is neither a public nor private key")
		}
	*/

	return
}

/*
// ParsePEM - parses PEM encoded bytes into signature key
func ParsePEM(pemBytes, password []byte) (signature *Signature, err error) {

	var key interface{}
	p, _ := pem.Decode(pemBytes) // for private key there should be no next
	keyBytes := p.Bytes          // decrypting PEM is no longer supported

	// identify key type to do proper decoding
	switch p.Type {

	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(keyBytes)

	case "RSA PRIVATE KEY", "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(keyBytes) // try to parse #PKCS#8 encoding
		if nil != err {
			key, err = x509.ParsePKCS1PrivateKey(keyBytes) // try to parse as PKCS#1
		}

	case "RSA PUBLIC KEY", "EC PUBLIC KEY", "PUBLIC KEY":
		key, err = x509.ParsePKIXPublicKey(keyBytes) // try to parse #PKCS#8 encoding
		if nil != err {
			key, err = x509.ParsePKCS1PublicKey(keyBytes) // try to parse as PKCS#1

		}

	}

	// if an error is found, return with indication where it happened
	if nil != err {
		return nil, fmt.Errorf("parsePEM: %s", err)
	}

	return New(key) // return new instance of Signature
}
*/
