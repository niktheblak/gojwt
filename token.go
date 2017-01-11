package jwt

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"
)

var Encoding = base64.RawURLEncoding

type Token struct {
	Context Context                `json:"-"`
	Header  map[string]interface{} `json:"header,omitempty"`
	Payload map[string]interface{} `json:"payload,omitempty"`
}

func (token *Token) Algorithm() string {
	return optString(token.Header, "alg")
}

func (token *Token) Type() string {
	return optString(token.Header, "typ")
}

func (token *Token) Expired() bool {
	exp, ok := token.Expiration()
	if ok {
		return exp.Before(time.Now())
	}
	return false
}

func (token *Token) UsedBeforeValidity() bool {
	nbf, ok := token.NotBefore()
	if ok {
		return nbf.After(time.Now())
	}
	return false
}

func (token *Token) Valid() bool {
	return !token.Expired() && !token.UsedBeforeValidity()
}

func (token *Token) Expiration() (time.Time, bool) {
	return optTimestamp(token.Payload, "exp")
}

func (token *Token) SetExpiration(ts time.Time) {
	token.Payload["exp"] = ts.Unix()
}

func (token *Token) Issuer() string {
	return optString(token.Payload, "iss")
}

func (token *Token) SetIssuer(issuer string) {
	token.Payload["iss"] = issuer
}

func (token *Token) Subject() string {
	return optString(token.Payload, "sub")
}

func (token *Token) SetSubject(subject string) {
	token.Payload["sub"] = subject
}

func (token *Token) Audience() string {
	return optString(token.Payload, "aud")
}

func (token *Token) SetAudience(audience string) {
	token.Payload["aud"] = audience
}

func (token *Token) IssuedAt() (time.Time, bool) {
	return optTimestamp(token.Payload, "iat")
}

func (token *Token) SetIssuedAt(ts time.Time) {
	token.Payload["iat"] = ts.Unix()
}

func (token *Token) NotBefore() (time.Time, bool) {
	return optTimestamp(token.Payload, "nbf")
}

func (token *Token) SetNotBefore(ts time.Time) {
	token.Payload["nbf"] = ts.Unix()
}

func (token *Token) SetClaim(key string, value interface{}) {
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
	if !token.Valid() {
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
	signature, err := Encoding.DecodeString(encodedSignature)
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
	signature, err := Encoding.DecodeString(encodedSignature)
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
	token.unmarshalTimestamps(encodedPayload)
	return token.Validate()
}

func (token *Token) unmarshalTimestamps(encodedPayload string) error {
	// json.Unmarshal decodes numbers to float64 if the target type is map[string]interface{}.
	// This is not good for integer timestamps so decode the timestamp again as int64.
	ts := struct {
		Expiration int64 `json:"exp"`
		NotBefore  int64 `json:"nbf"`
		IssuedAt   int64 `json:"iat"`
	}{}
	err := decodeBase64JSON(encodedPayload, &ts)
	if err != nil {
		return err
	}
	if ts.Expiration != 0 {
		token.Payload["exp"] = ts.Expiration
	}
	if ts.NotBefore != 0 {
		token.Payload["nbf"] = ts.NotBefore
	}
	if ts.IssuedAt != 0 {
		token.Payload["iat"] = ts.IssuedAt
	}
	return nil
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

func optString(m map[string]interface{}, key string) string {
	rawValue, ok := m[key]
	if !ok {
		return ""
	}
	value, ok := rawValue.(string)
	if !ok {
		return ""
	}
	return value
}

func optTimestamp(m map[string]interface{}, key string) (time.Time, bool) {
	rawTS, ok := m[key]
	if !ok {
		return time.Time{}, false
	}
	ts, ok := rawTS.(int64)
	if !ok {
		return time.Time{}, false
	}
	return time.Unix(ts, 0), true
}
