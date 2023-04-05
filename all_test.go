package signature

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"testing"

	"github.com/lestrrat-go/jwx/jwk"
)

func TestSignatureEC(t *testing.T) {

	privateKey, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	//pubKey := privateKey.PublicKey

	p := *privateKey
	signSig, err := New(p)
	if nil != err {
		fmt.Println(err)
		os.Exit(1)
	}

	verifySig, err := New(&privateKey.PublicKey)
	if nil != err {
		fmt.Println(err)
		os.Exit(1)
	}

	signSig.Set("iss", "issuer")
	signSig.Set("clientId", "randomid")

	hashed := sha256.Sum256([]byte("hello world"))
	signSig.Set("hash", hex.EncodeToString(hashed[:]))

	type example struct {
		Key   string `json:"key"`
		Value string `json:"value"`
	}

	var e example
	e.Key = "bingo"
	e.Value = "book"

	signSig.Set("myvalue", e)

	signed, err := signSig.Generate()
	if nil != err {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println(string(signed))

	payload, err := verifySig.Verify(signed)
	if nil != err {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println(string(payload))

}

func TestSignatureRSA(t *testing.T) {

	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	//pubKey := privateKey.PublicKey

	p := *privateKey
	sigSign, err := New(p)
	if nil != err {
		fmt.Println(err)
		os.Exit(1)
	}

	sigVerify, err := New(&privateKey.PublicKey)
	if nil != err {
		fmt.Println(err)
		os.Exit(1)
	}
	sigSign.Set("iss", "issuer")
	sigSign.Set("clientId", "randomid")

	hashed := sha256.Sum256([]byte("hello world"))
	sigSign.Set("hash", hex.EncodeToString(hashed[:]))

	type example struct {
		Key   string `json:"key"`
		Value string `json:"value"`
	}

	var e example
	e.Key = "bingo"
	e.Value = "book"

	sigSign.Set("myvalue", e)

	signed, err := sigSign.Generate()
	if nil != err {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println(string(signed))

	payload, err := sigVerify.Verify(signed)
	if nil != err {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println(string(payload))

}

func TestSignaturePEM(t *testing.T) {

	// EC key
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	pemBlockPrivate := &pem.Block{
		Type: "EC PRIVATE KEY",
	}
	pemBlockPrivate.Bytes, _ = x509.MarshalECPrivateKey(privateKey)

	pemBlockPublic := &pem.Block{
		Type: "PUBLIC KEY",
	}
	pemBlockPublic.Bytes, _ = x509.MarshalPKIXPublicKey(&privateKey.PublicKey)

	pemBytesPrivate := pem.EncodeToMemory(pemBlockPrivate)
	pemBytesPublic := pem.EncodeToMemory(pemBlockPublic)

	fmt.Println(string(pemBytesPrivate))
	fmt.Println(string(pemBytesPublic))

	sigSign, err := ParsePEM(pemBytesPrivate, nil)
	if nil != err {
		fmt.Println(err)
		os.Exit(1)
	}

	sigVerify, err := ParsePEM(pemBytesPublic, nil)
	if nil != err {
		fmt.Println(err)
		os.Exit(1)
	}

	sigSign.Set("iss", "issuer")

	signed, err := sigSign.Generate()
	if nil != err {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println(string(signed))

	payload, err := sigVerify.Verify(signed)
	if nil != err {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println(string(payload))

}

func TestSignatureJWK(t *testing.T) {

	// RSA key
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	// EC key
	//privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	publicKey := privateKey.PublicKey

	jwkPriv, err := jwk.New(privateKey)
	if nil != err {
		fmt.Println(err)
		os.Exit(1)
	}

	jwkPub, err := jwk.New(publicKey)
	if nil != err {
		fmt.Println(err)
		os.Exit(1)
	}

	jwkPrivBytes, _ := json.Marshal(jwkPriv)
	//fmt.Println(string(jwkPrivBytes))

	jwkPubBytes, _ := json.Marshal(jwkPub)
	//fmt.Println(string(jwkPubBytes))

	sigSign, err := ParseJWK(jwkPrivBytes)
	if nil != err {
		fmt.Println(err)
		os.Exit(1)
	}

	sigVerify, err := ParseJWK(jwkPubBytes)
	if nil != err {
		fmt.Println(err)
		os.Exit(1)
	}

	sigSign.Set("iss", "issuer")

	signed, err := sigSign.Generate()
	if nil != err {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println(string(signed))

	payload, err := sigVerify.Verify(signed)
	if nil != err {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println(string(payload))

}

func TestSignatureED25519(t *testing.T) {

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if nil != err {
		fmt.Println(err)
		os.Exit(1)
	}

	signSig, err := New(privateKey)
	if nil != err {
		fmt.Println(err)
		os.Exit(1)
	}

	verifySig, err := New(publicKey)
	if nil != err {
		fmt.Println(err)
		os.Exit(1)
	}

	signSig.Set("iss", "issuer")
	signSig.Set("clientId", "ed25519-randomid")

	hashed := sha256.Sum256([]byte("hello world"))
	signSig.Set("hash", hex.EncodeToString(hashed[:]))

	type example struct {
		Key   string `json:"key"`
		Value string `json:"value"`
	}

	var e example
	e.Key = "bingo"
	e.Value = "book"

	signSig.Set("myvalue", e)

	signed, err := signSig.Generate()
	if nil != err {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println(string(signed))

	payload, err := verifySig.Verify(signed)
	if nil != err {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println(string(payload))

}
