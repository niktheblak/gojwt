package jwt

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"

	"github.com/niktheblak/jwt/errors"
	"github.com/niktheblak/jwt/sign"
	"github.com/niktheblak/jwt/sign/algorithm"
)

const DefaultType = "JWT"

var (
	DefaultSigner sign.Signer
	defaultHeader map[string]interface{}
)

func SetDefaultSigner(sig sign.Signer) {
	DefaultSigner = sig
	defaultHeader = createHeader(sig)
}

type Token struct {
	signer sign.Signer
	header map[string]interface{}
	Claims map[string]interface{}
}

func New() *Token {
	if DefaultSigner == nil {
		panic("SetDefaultSigner has not been called")
	}
	return newToken(DefaultSigner, defaultHeader, make(map[string]interface{}))
}

func NewWithClaims(claims map[string]interface{}) *Token {
	if DefaultSigner == nil {
		panic("SetDefaultSigner has not been called")
	}
	return newToken(DefaultSigner, defaultHeader, claims)
}

func NewWithHeaderAndClaims(header, claims map[string]interface{}) *Token {
	if DefaultSigner == nil {
		panic("SetDefaultSigner has not been called")
	}
	return newToken(DefaultSigner, header, claims)
}

func NewWithSigner(sig sign.Signer) *Token {
	header := createHeader(sig)
	header["typ"] = DefaultType
	header["alg"] = sig.Algorithm().Name
	return &Token{
		signer: sig,
		header: header,
		Claims: make(map[string]interface{}),
	}
}

func NewWithSignerAndClaims(sig sign.Signer, claims map[string]interface{}) *Token {
	header := createHeader(sig)
	return &Token{
		signer: sig,
		header: header,
		Claims: claims,
	}
}

func newToken(sig sign.Signer, header, claims map[string]interface{}) *Token {
	if sig.Algorithm().Name != header["alg"] {
		panic("Algorithm used with signer does not match the one given in header")
	}
	return &Token{
		signer: sig,
		header: header,
		Claims: claims,
	}
}

var DefaultEncoding = base64.RawURLEncoding

func (token *Token) Header(key string) interface{} {
	return token.header[key]
}

func (token *Token) SetHeader(key string, value interface{}) {
	if &token.header == &defaultHeader {
		token.header = make(map[string]interface{})
	}
	token.header[key] = value
}

func (token *Token) Algorithm() (algo algorithm.Algorithm) {
	name, ok := token.header["alg"]
	if !ok {
		return
	}
	algo = algorithm.Algorithms[name.(string)]
	return
}

func (token *Token) Type() (typ string) {
	t, ok := token.header["typ"]
	if ok {
		typ = t.(string)
	}
	return
}

func (token *Token) Expired() bool {
	ts, ok := token.Claims["exp"]
	if ok {
		tsint := ts.(int64)
		exp := time.Unix(tsint, 0)
		return exp.Before(time.Now())
	}
	return false
}

func (token *Token) Expiration() (time.Time, bool) {
	ts, ok := token.Claims["exp"]
	if ok {
		tsint := ts.(int64)
		exp := time.Unix(tsint, 0)
		return exp, true
	}
	return time.Time{}, false
}

func (token *Token) SetExpiration(exp time.Time) {
	token.Claims["exp"] = exp.Unix()
}

func (token *Token) Validate() error {
	if token.Algorithm().Name != token.signer.Algorithm().Name {
		return errors.ErrInvalidAlgorithm
	}
	if token.Type() != "JWT" {
		return errors.ErrInvalidType
	}
	if token.Expired() {
		return errors.ErrExpiredToken
	}
	return nil
}

func (token *Token) Encode() (string, error) {
	var buf bytes.Buffer
	encoder := base64.NewEncoder(DefaultEncoding, &buf)
	headerJSON, err := json.Marshal(token.header)
	if err != nil {
		return "", err
	}
	encoder.Write(headerJSON)
	buf.WriteByte('.')
	claimsJSON, err := json.Marshal(token.Claims)
	if err != nil {
		return "", err
	}
	encoder.Write(claimsJSON)
	signature := token.signer.Sign(buf.String())
	buf.WriteByte('.')
	encoder.Write(signature)
	encoder.Close()
	return buf.String(), nil
}

func (token *Token) Decode(tokenStr string) (err error) {
	claimsPos := strings.IndexByte(tokenStr, '.')
	if claimsPos == -1 {
		err = errors.ErrMalformedToken
		return
	}
	signaturePos := strings.LastIndexByte(tokenStr, '.')
	if signaturePos == claimsPos {
		err = errors.ErrMalformedToken
		return
	}
	encodedPayload := tokenStr[:signaturePos]
	encodedHeader := tokenStr[:claimsPos]
	encodedClaims := tokenStr[claimsPos+1 : signaturePos]
	encodedSignature := tokenStr[signaturePos+1:]
	// Verify signature
	signature, err := DefaultEncoding.DecodeString(encodedSignature)
	if err != nil {
		return
	}
	err = token.signer.Verify(encodedPayload, signature)
	if err != nil {
		return
	}
	// Decode header
	token.header = make(map[string]interface{})
	err = decodeBase64JSON(encodedHeader, &token.header)
	if err != nil {
		return
	}
	// Decode claims
	token.Claims = make(map[string]interface{})
	err = decodeBase64JSON(encodedClaims, &token.Claims)
	if err != nil {
		return
	}
	err = token.Validate()
	return
}

func (token *Token) VerifySignature(tokenStr string) error {
	signaturePos := strings.LastIndexByte(tokenStr, '.')
	if signaturePos == -1 {
		return errors.ErrMalformedToken
	}
	encodedPayload := tokenStr[:signaturePos]
	encodedSignature := tokenStr[signaturePos+1:]
	signature, err := DefaultEncoding.DecodeString(encodedSignature)
	if err != nil {
		return err
	}
	return token.signer.Verify(encodedPayload, signature)
}

func decodeBase64JSON(data string, v interface{}) error {
	decoded, err := DefaultEncoding.DecodeString(data)
	if err != nil {
		return err
	}
	err = json.Unmarshal(decoded, v)
	if err != nil {
		return err
	}
	return nil
}

func createHeader(sig sign.Signer) map[string]interface{} {
	header := make(map[string]interface{})
	header["typ"] = DefaultType
	header["alg"] = sig.Algorithm().Name
	return header
}
