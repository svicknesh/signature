package signature_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/svicknesh/key/v2"
	"github.com/svicknesh/signature"
)

func TestSignatureEC(t *testing.T) {

	//privateKey, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	//pubKey := privateKey.PublicKey
	//p := *privateKey

	k, err := key.GenerateKey(key.ECDSA384)
	if nil != err {
		fmt.Println(err)
		os.Exit(1)
	}

	privKeyBytes, err := k.Bytes()
	if nil != err {
		fmt.Println(err)
		os.Exit(1)
	}

	signSig, err := signature.FromJWK(privKeyBytes)
	if nil != err {
		fmt.Println(err)
		os.Exit(1)
	}

	pubkey, err := k.PublicKey()
	if nil != err {
		fmt.Println(err)
		os.Exit(1)
	}

	pubKeyBytes, err := pubkey.Bytes()
	if nil != err {
		fmt.Println(err)
		os.Exit(1)
	}

	verifySig, err := signature.FromJWK(pubKeyBytes)
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

	k, err := key.GenerateKey(key.RSA2048)
	if nil != err {
		fmt.Println(err)
		os.Exit(1)
	}

	privKeyBytes, err := k.Bytes()
	if nil != err {
		fmt.Println(err)
		os.Exit(1)
	}

	signSig, err := signature.FromJWK(privKeyBytes)
	if nil != err {
		fmt.Println(err)
		os.Exit(1)
	}

	pubkey, err := k.PublicKey()
	if nil != err {
		fmt.Println(err)
		os.Exit(1)
	}

	pubKeyBytes, err := pubkey.Bytes()
	if nil != err {
		fmt.Println(err)
		os.Exit(1)
	}

	verifySig, err := signature.FromJWK(pubKeyBytes)
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

/*
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

	signSig, err := signature.ParsePEM(pemBytesPrivate, nil)
	if nil != err {
		fmt.Println(err)
		os.Exit(1)
	}

	verifySig, err := signature.ParsePEM(pemBytesPublic, nil)
	if nil != err {
		fmt.Println(err)
		os.Exit(1)
	}

	signSig.Set("iss", "issuer")

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
*/

func TestSignatureJWK(t *testing.T) {

	// RSA key
	//privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	// EC key
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	publicKey := privateKey.PublicKey

	jwkPriv, err := key.NewFromRawKey(privateKey)
	if nil != err {
		fmt.Println(err)
		os.Exit(1)
	}
	jwkPrivBytes, _ := jwkPriv.Bytes()
	fmt.Println(string(jwkPrivBytes))

	jwkPub, err := key.NewFromRawKey(publicKey)
	if nil != err {
		fmt.Println(err)
		os.Exit(1)
	}
	jwkPubBytes, _ := jwkPub.Bytes()
	fmt.Println(string(jwkPubBytes))

	signSig, err := signature.FromJWK(jwkPrivBytes)
	if nil != err {
		fmt.Println(err)
		os.Exit(1)
	}
	//fmt.Println(signSig)

	verifySig, err := signature.FromJWK(jwkPubBytes)
	if nil != err {
		fmt.Println(err)
		os.Exit(1)
	}

	signSig.Set("iss", "issuer")

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

func TestSignatureED25519(t *testing.T) {

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if nil != err {
		fmt.Println(err)
		os.Exit(1)
	}

	signSig, err := signature.FromRaw(privateKey)
	if nil != err {
		fmt.Println(err)
		os.Exit(1)
	}

	verifySig, err := signature.FromRaw(publicKey)
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

func TestOauth2(t *testing.T) {

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if nil != err {
		fmt.Println(err)
		os.Exit(1)
	}

	oa, err := signature.NewTokenOAuth2(privateKey)
	if nil != err {
		fmt.Println(err)
		os.Exit(1)
	}

	oa.SetIssuedAt(time.Now().Add(time.Hour))
	oa.SetExpiry(time.Hour * 2)

	oa.SetIssuer("memyselfi")
	oa.SetTokenIdentifier("1234567890")
	oa.SetAudience("coolremoteserver")
	oa.SetSubject("iamtheissuer")
	oa.SetClientID("thematrix")

	sig, err := oa.Generate()
	if nil != err {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println(string(sig))

	s, err := signature.FromRaw(publicKey)
	if nil != err {
		fmt.Println(err)
		os.Exit(1)
	}

	payload, err := s.Verify(sig)
	if nil != err {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println(string(payload))

}

func TestJWT(t *testing.T) {

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if nil != err {
		fmt.Println(err)
		os.Exit(1)
	}

	myjwt, err := signature.NewTokenJWT(privateKey)
	if nil != err {
		fmt.Println(err)
		os.Exit(1)
	}

	myjwt.SetIssuedAt(time.Now().Add(time.Hour))
	myjwt.SetExpiry(time.Hour * 2)

	myjwt.SetIssuer("jwt-memyselfi")
	myjwt.SetTokenIdentifier("jwt-1234567890")
	myjwt.SetAudience("jwt-coolremoteserver")
	myjwt.SetSubject("jwt-iamtheissuer")

	sig, err := myjwt.Generate()
	if nil != err {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println(string(sig))

	s, err := signature.FromRaw(publicKey)
	if nil != err {
		fmt.Println(err)
		os.Exit(1)
	}

	payload, err := s.Verify(sig)
	if nil != err {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println(string(payload))

}
