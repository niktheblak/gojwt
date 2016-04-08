package jwt

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"

	"github.com/niktheblak/jwt/sign"
)

const DefaultType = "JWT"

var (
	DefaultEncoding = base64.RawURLEncoding
	defaultSigner   sign.Signer
)

func SetDefaultSigner(sig sign.Signer) {
	defaultSigner = sig
}

type Token struct {
	Signer sign.Signer
	Header map[string]interface{}
	Claims map[string]interface{}
}

func New() Token {
	if defaultSigner == nil {
		panic("SetDefaultSigner has not been called")
	}
	return Token{
		Signer: defaultSigner,
		Header: createHeader(defaultSigner),
		Claims: make(map[string]interface{}),
	}
}

func NewWithClaims(claims map[string]interface{}) Token {
	if defaultSigner == nil {
		panic("SetDefaultSigner has not been called")
	}
	return Token{
		Signer: defaultSigner,
		Header: createHeader(defaultSigner),
		Claims: claims,
	}
}

func NewWithHeaderAndClaims(header, claims map[string]interface{}) Token {
	if defaultSigner == nil {
		panic("SetDefaultSigner has not been called")
	}
	if defaultSigner.Algorithm() != header["alg"] {
		panic("Algorithm used with signer does not match the one given in header")
	}
	return Token{
		Signer: defaultSigner,
		Header: header,
		Claims: claims,
	}
}

func (token Token) Algorithm() string {
	return token.Header["alg"].(string)
}

func (token Token) Type() string {
	return token.Header["typ"].(string)
}

func (token Token) Expired() bool {
	exp, ok := token.Expiration()
	if ok {
		return exp.Before(time.Now())
	}
	return false
}

func (token Token) Expiration() (time.Time, bool) {
	if ts, ok := token.Claims["exp"]; ok {
		return toTimeStamp(ts)
	}
	return time.Time{}, false
}

func (token *Token) SetExpiration(exp time.Time) {
	token.Claims["exp"] = exp.Unix()
}

func (token Token) Validate() error {
	if err := token.validateSigner(); err != nil {
		return err
	}
	if token.Algorithm() != token.Signer.Algorithm() {
		return ErrInvalidAlgorithm
	}
	if token.Type() != DefaultType {
		return ErrInvalidType
	}
	if token.Expired() {
		return ErrExpiredToken
	}
	return nil
}

func (token Token) Encode() (string, error) {
	if err := token.validateSigner(); err != nil {
		return "", err
	}
	if err := token.validateHeader(); err != nil {
		return "", err
	}
	var buf bytes.Buffer
	encoder := base64.NewEncoder(DefaultEncoding, &buf)
	headerJSON, err := json.Marshal(token.Header)
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
	signature := token.Signer.Sign(buf.String())
	buf.WriteByte('.')
	encoder.Write(signature)
	encoder.Close()
	return buf.String(), nil
}

func (token *Token) Decode(tokenStr string) error {
	if err := token.validateSigner(); err != nil {
		return err
	}
	claimsPos := strings.IndexByte(tokenStr, '.')
	if claimsPos == -1 {
		return ErrMalformedToken
	}
	signaturePos := strings.LastIndexByte(tokenStr, '.')
	if signaturePos == claimsPos {
		return ErrMalformedToken
	}
	encodedPayload := tokenStr[:signaturePos]
	encodedHeader := tokenStr[:claimsPos]
	encodedClaims := tokenStr[claimsPos+1 : signaturePos]
	encodedSignature := tokenStr[signaturePos+1:]
	// Verify signature
	signature, err := DefaultEncoding.DecodeString(encodedSignature)
	if err != nil {
		return err
	}
	err = token.Signer.Verify(encodedPayload, signature)
	if err != nil {
		return err
	}
	// Decode header
	token.Header = make(map[string]interface{})
	err = decodeBase64JSON(encodedHeader, &token.Header)
	if err != nil {
		return err
	}
	// Decode claims
	token.Claims = make(map[string]interface{})
	err = decodeBase64JSON(encodedClaims, &token.Claims)
	if err != nil {
		return err
	}
	return token.Validate()
}

func (token Token) VerifySignature(tokenStr string) error {
	if err := token.validateSigner(); err != nil {
		return err
	}
	signaturePos := strings.LastIndexByte(tokenStr, '.')
	if signaturePos == -1 {
		return ErrMalformedToken
	}
	encodedPayload := tokenStr[:signaturePos]
	encodedSignature := tokenStr[signaturePos+1:]
	signature, err := DefaultEncoding.DecodeString(encodedSignature)
	if err != nil {
		return err
	}
	return token.Signer.Verify(encodedPayload, signature)
}

func (token Token) validateSigner() error {
	if token.Signer == nil && defaultSigner == nil {
		return ErrMissingSigner
	}
	return nil
}

func (token Token) validateHeader() error {
	if token.Header == nil {
		return ErrMissingHeader
	}
	if _, ok := token.Header["typ"]; !ok {
		return ErrMissingType
	}
	if _, ok := token.Header["alg"]; !ok {
		return ErrMissingAlgorithm
	}
	return nil
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
	header["alg"] = sig.Algorithm()
	return header
}

func toTimeStamp(s interface{}) (ts time.Time, ok bool) {
	ok = true
	var tsInt int64
	switch t := s.(type) {
	case float32:
		tsInt = int64(t)
	case float64:
		tsInt = int64(t)
	case int:
		tsInt = int64(t)
	case uint:
		tsInt = int64(t)
	case int64:
		tsInt = t
	case uint64:
		tsInt = int64(t)
	default:
		ok = false
		return
	}
	ts = time.Unix(tsInt, 0)
	return
}
