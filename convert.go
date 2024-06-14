package signature

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/lestrrat-go/jwx/v2/jwk"
)

// ParsePEM - parses PEM encoded bytes into a key
func ParsePEM(pemBytes, password []byte) (signature *Signature, err error) {

	var key interface{}
	p, _ := pem.Decode(pemBytes) // for private key there should be no next

	var keyBytes []byte
	if x509.IsEncryptedPEMBlock(p) {
		keyBytes, err = x509.DecryptPEMBlock(p, password)
		if nil != err {
			return nil, fmt.Errorf("parsePEM: %s", err)
		}
	} else {
		keyBytes = p.Bytes
	}

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

// ParseJWK - parses JWK JSON encoded bytes into a key
func ParseJWK(jsonBytes []byte) (signature *Signature, err error) {

	var key interface{}

	j, err := jwk.ParseKey(jsonBytes)
	if err != nil {
		return nil, fmt.Errorf("parseJWK: %w", err)
	}

	if err = j.Raw(&key); err != nil {
		return nil, fmt.Errorf("parseJWK: %w", err)
	}

	// by default we only have 1 set of key so we don't have to loop
	/*
		set, err := jwk.Parse(jsonBytes)
		if err != nil {
			return nil, fmt.Errorf("parseJWK: %s", err)
		}

		for it := set.Iterate(context.Background()); it.Next(context.Background()); {
			pair := it.Pair()
			k := pair.Value.(jwk.Key)

			if err = k.Raw(&key); err != nil {
				return nil, fmt.Errorf("parseJWK: %s", err)
			}
		}
	*/

	return New(key) // return new instance of Signature
}
