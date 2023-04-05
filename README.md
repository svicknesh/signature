# Signature

Golang helper library to create JSON Web Signatures (JWS) for whatever use case you may think off. Some of the potential use cases are
- Authorization tokens using public/private key.
- File integrity checking for each individual.
- Creating revision information and signing them to prevent tampering.
- and so many other ideas ...

JWS is the basis for JWT and others that are derived from JWT. This libary **ONLY** generates and verifies the signature portion, not the payload. The payload checking is left to the application using this library, allowing it to offer more control on the payload validation.

## Note on `JWT` or `Oauth2`
To generate a general JWT, create an instance of `Signature` and add the following fields
- `iss` - issuer of the token.
- `iat` - Unix timestamp (preferably in UTC) when this token was issued (OPTIONAL).
- `nbf` - Unix timestamp (preferably in UTC) when this token can be used, should be equivalent or greater than `iat` (OPTIONAL).
- `exp` - Unix timestamp (preferably in UTC) when this token expires.
- `sub` - subject of the token.
- `aud` - who is this token targetted to.
` jti` - Unique identifier of **THIS** JWT (OPTIONAL).

To generaet an Oauth2 token, create an instance of `Signature` and add the following fields
- Use the above JWT as the base with `iss`, `iat`, `exp`, `aud`, `sub` and `jti` being **REQUIRED**.
- `client_id` - public identifier of the application, unique in the scope of the application using it.
- `scope` - space separated values indicating what the permission scope of this token is.


## Usage

### Generating signature

Generating a signature requires either an `RSA`, `ECDSA` or `ED25519` private key.

```go

// `RSA`, `ECDSA` or `ED25519` private key already exists
sig, err := signature.New(privateKey)
if nil != err {
    fmt.Println(err)
    os.Exit(1)
}

sig.Set("iss", "issuer")
sig.Set("clientId", "randomid")

hashed := sha256.Sum256([]byte("hello world"))
sig.Set("hash", hex.EncodeToString(hashed[:]))

type example struct {
    Key   string `json:"key"`
    Value string `json:"value"`
}

var e example
e.Key = "bingo"
e.Value = "book"

sig.Set("myvalue", e)

signed, err := sig.Generate()
if nil != err {
    fmt.Println(err)
    os.Exit(1)
}
fmt.Println(string(signed))

```


### Verifying signature

Generating a signature requires either an `RSA`, `ECDSA` or `ED25519` public key.


```go

// `RSA`, `ECDSA` or `ED25519` public key already exists

sig, err := signature.New(publicKey)
if nil != err {
    fmt.Println(err)
    os.Exit(1)
}

// the signed value in bytes
payload, err := sig.Verify(signed)
if nil != err {
    fmt.Println(err)
    os.Exit(1)
}
fmt.Println(string(payload))

```


### Reading PEM encoded public/private keys into `Signature` instance

Helper function to read a public/private key encoded in PEM format into `Signature` instance. Supports both PKCS#1 or PKCS#8 format

```go

// keyBytes are the bytes of PEM contents
sig, err := signature.ParsePEM(keyBytes, nil)
if nil != err {
    fmt.Println(err)
    os.Exit(1)
}

// returns an instance of Signature for use in the application

```


### Reading JWK JSON encoded public/private keys into `Signature` instance

Helper function to read a public/private key encoded in JWK JSON string format into `Signature` instance.

```go

// keyBytes are the bytes of the JSON string
key, err := signature.ParseJWK(keyBytes, nil)
if nil != err {
    fmt.Println(err)
    os.Exit(1)
}

// returns an instance of Signature for use in the application

```
