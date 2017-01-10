package token

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"
)

var encoding = base64.RawURLEncoding

type Token struct {
	Context Context                `json:"-"`
	Header  map[string]interface{} `json:"header,omitempty"`
	Payload map[string]interface{} `json:"payload,omitempty"`
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
	ts, ok := token.Payload["exp"]
	if !ok {
		return time.Time{}, false
	}
	tsInt, ok := ts.(int64)
	if !ok {
		return time.Time{}, false
	}
	return time.Unix(tsInt, 0), true
}

func (token *Token) SetExpiration(exp time.Time) {
	token.Payload["exp"] = exp.Unix()
}

func (token *Token) AddClaim(key string, value interface{}) {
	token.Payload[key] = value
}

func (token *Token) Validate() error {
	algo, ok := token.Header["alg"]
	if !ok {
		return ErrMalformedToken
	}
	if algo != token.Context.Signer().Algorithm() {
		return ErrInvalidAlgorithm
	}
	typ, ok := token.Header["typ"]
	if !ok {
		return ErrMalformedToken
	}
	if typ != token.Context.Type() {
		return ErrInvalidType
	}
	if token.Expired() {
		return ErrExpiredToken
	}
	return nil
}

func (token *Token) Encode() (tokenString string, err error) {
	if err = token.validateHeader(); err != nil {
		return
	}
	buf := new(bytes.Buffer)
	if err = encodeBase64JSON(token.Header, buf); err != nil {
		return
	}
	err = buf.WriteByte('.')
	if err != nil {
		return
	}
	if err = encodeBase64JSON(token.Payload, buf); err != nil {
		return
	}
	signature := token.Context.Signer().Sign(buf.String())
	err = buf.WriteByte('.')
	if err != nil {
		return
	}
	if err = encodeBase64(signature, buf); err != nil {
		return
	}
	tokenString = buf.String()
	return
}

func (token *Token) VerifySignature(tokenStr string) error {
	signaturePos := strings.LastIndexByte(tokenStr, '.')
	if signaturePos == -1 {
		return ErrMalformedToken
	}
	encodedPayload := tokenStr[:signaturePos]
	encodedSignature := tokenStr[signaturePos+1:]
	signature, err := encoding.DecodeString(encodedSignature)
	if err != nil {
		return err
	}
	return token.Context.Signer().Verify(encodedPayload, signature)
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
	encodedContent := tokenStr[:signaturePos]
	encodedHeader := tokenStr[:claimsPos]
	encodedPayload := tokenStr[claimsPos+1 : signaturePos]
	encodedSignature := tokenStr[signaturePos+1:]
	// Verify signature
	signature, err := encoding.DecodeString(encodedSignature)
	if err != nil {
		return err
	}
	err = token.Context.Signer().Verify(encodedContent, signature)
	if err != nil {
		return err
	}
	// Decode header
	token.Header = make(map[string]interface{})
	err = decodeBase64JSON(encodedHeader, &token.Header)
	if err != nil {
		return err
	}
	// Decode payload
	token.Payload = make(map[string]interface{})
	err = decodeBase64JSON(encodedPayload, &token.Payload)
	if err != nil {
		return err
	}
	if _, hasExp := token.Payload["exp"]; hasExp {
		// json.Unmarshal decodes numbers to float64 if the target type is map[string]interface{}.
		// This is not good for integer timestamps so decode the timestamp again as int64.
		exp := struct {
			Expiration int64 `json:"exp"`
		}{}
		err = decodeBase64JSON(encodedPayload, &exp)
		if err != nil {
			return err
		}
		if exp.Expiration != 0 {
			token.Payload["exp"] = exp.Expiration
		}
	}
	return token.Validate()
}

func (token *Token) String() string {
	buf := new(bytes.Buffer)
	enc := json.NewEncoder(buf)
	enc.SetIndent("", "    ")
	enc.Encode(token)
	return buf.String()
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
