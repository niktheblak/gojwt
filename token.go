package jwt

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"
)

type Token struct {
	Context Context
	Header  map[string]interface{}
	Claims  map[string]interface{}
}

func (token *Token) Algorithm() string {
	return token.Header["alg"].(string)
}

func (token *Token) Type() string {
	return token.Header["typ"].(string)
}

func (token *Token) Expired() bool {
	exp, ok := token.Expiration()
	if ok {
		return exp.Before(time.Now())
	}
	return false
}

func (token *Token) Expiration() (time.Time, bool) {
	if ts, ok := token.Claims["exp"]; ok {
		return toTimeStamp(ts)
	}
	return time.Time{}, false
}

func (token *Token) SetExpiration(exp time.Time) {
	token.Claims["exp"] = exp.Unix()
}

func (token *Token) Validate() error {
	if token.Algorithm() != token.Context.Signer().Algorithm() {
		return ErrInvalidAlgorithm
	}
	if token.Type() != token.Context.Type() {
		return ErrInvalidType
	}
	if token.Expired() {
		return ErrExpiredToken
	}
	return nil
}

func (token *Token) Encode() (string, error) {
	if err := token.validateHeader(); err != nil {
		return "", err
	}
	var buf bytes.Buffer
	encoder := base64.NewEncoder(token.Context.Encoding(), &buf)
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
	signature := token.Context.Signer().Sign(buf.String())
	buf.WriteByte('.')
	encoder.Write(signature)
	encoder.Close()
	return buf.String(), nil
}

func (token *Token) Decode(tokenStr string) error {
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
	signature, err := token.Context.Encoding().DecodeString(encodedSignature)
	if err != nil {
		return err
	}
	err = token.Context.Signer().Verify(encodedPayload, signature)
	if err != nil {
		return err
	}
	// Decode header
	token.Header = make(map[string]interface{})
	err = token.decodeBase64JSON(encodedHeader, &token.Header)
	if err != nil {
		return err
	}
	// Decode claims
	token.Claims = make(map[string]interface{})
	err = token.decodeBase64JSON(encodedClaims, &token.Claims)
	if err != nil {
		return err
	}
	return token.Validate()
}

func (token *Token) VerifySignature(tokenStr string) error {
	signaturePos := strings.LastIndexByte(tokenStr, '.')
	if signaturePos == -1 {
		return ErrMalformedToken
	}
	encodedPayload := tokenStr[:signaturePos]
	encodedSignature := tokenStr[signaturePos+1:]
	signature, err := token.Context.Encoding().DecodeString(encodedSignature)
	if err != nil {
		return err
	}
	return token.Context.Signer().Verify(encodedPayload, signature)
}

func (token *Token) validateHeader() error {
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

func (token *Token) decodeBase64JSON(data string, v interface{}) error {
	decoded, err := token.Context.Encoding().DecodeString(data)
	if err != nil {
		return err
	}
	err = json.Unmarshal(decoded, v)
	if err != nil {
		return err
	}
	return nil
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
