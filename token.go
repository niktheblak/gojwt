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

func New() *Token {
	if defaultSigner == nil {
		panic("SetDefaultSigner has not been called")
	}
	return &Token{
		Signer: defaultSigner,
		Header: createHeader(defaultSigner),
		Claims: make(map[string]interface{}),
	}
}

func NewWithClaims(claims map[string]interface{}) *Token {
	if defaultSigner == nil {
		panic("SetDefaultSigner has not been called")
	}
	return &Token{
		Signer: defaultSigner,
		Header: createHeader(defaultSigner),
		Claims: claims,
	}
}

func NewWithHeaderAndClaims(header, claims map[string]interface{}) *Token {
	if defaultSigner == nil {
		panic("SetDefaultSigner has not been called")
	}
	if defaultSigner.Algorithm().Name != header["alg"] {
		panic("Algorithm used with signer does not match the one given in header")
	}
	return &Token{
		Signer: defaultSigner,
		Header: header,
		Claims: claims,
	}
}

func (token *Token) Algorithm() (algo algorithm.Algorithm) {
	name, ok := token.Header["alg"]
	if !ok {
		return
	}
	algo = algorithm.Algorithms[name.(string)]
	return
}

func (token *Token) Type() (typ string) {
	t, ok := token.Header["typ"]
	if ok {
		typ = t.(string)
	}
	return
}

func (token *Token) Expired() bool {
	exp, ok := token.Expiration()
	if ok {
		return exp.Before(time.Now())
	}
	return false
}

func (token *Token) Expiration() (time.Time, bool) {
	ts, ok := token.Claims["exp"]
	if ok {
		exp, ok := toTimeStamp(ts)
		return exp, ok
	}
	return time.Time{}, false
}

func (token *Token) SetExpiration(exp time.Time) {
	token.Claims["exp"] = exp.Unix()
}

func (token *Token) Validate() error {
	token.checkSigner()
	if token.Algorithm().Name != token.Signer.Algorithm().Name {
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
	token.checkSigner()
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

func (token *Token) Decode(tokenStr string) (err error) {
	token.checkSigner()
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
	err = token.Signer.Verify(encodedPayload, signature)
	if err != nil {
		return
	}
	// Decode header
	token.Header = make(map[string]interface{})
	err = decodeBase64JSON(encodedHeader, &token.Header)
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
	token.checkSigner()
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
	return token.Signer.Verify(encodedPayload, signature)
}

func (token *Token) checkSigner() {
	if token.Signer == nil && defaultSigner == nil {
		panic("Neither token signer nor default signer has not been set")
	}
	if token.Signer == nil {
		token.Signer = defaultSigner
	}
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
