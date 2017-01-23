/*
  Copyright 2017 Niko Korhonen

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
 */

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

func (token *Token) Expiration() (time.Time, bool) {
	return optTimestamp(token.Payload, "exp")
}

func (token *Token) SetExpiration(ts time.Time) {
	token.Payload["exp"] = ts.Unix()
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

func (token *Token) Valid() bool {
	exp, hasExpiration := token.Expiration()
	if hasExpiration {
		// Token has expired
		if time.Now().After(exp) {
			return false
		}
	}
	nbf, hasNotBefore := token.NotBefore()
	if hasNotBefore {
		// Token used before validity begins
		if time.Now().Before(nbf) {
			return false
		}
	}
	iat, hasIssuedAt := token.IssuedAt()
	if hasIssuedAt {
		if time.Now().Before(iat) {
			// Token was issued in the future
			return false
		}
	}
	if hasExpiration && hasIssuedAt {
		if exp.Before(iat) {
			// Token expired before it was issued
			return false
		}
	}
	if hasExpiration && hasNotBefore {
		// Token expires before validity begins
		if exp.Before(nbf) {
			return false
		}
	}

	return true
}

func (token *Token) Validate() error {
	if token.Context == nil {
		return ErrContextNotSet
	}
	algo, ok := token.Header["alg"]
	if !ok {
		return ErrInvalidHeader
	}
	if algo != token.Context.Signer().Algorithm() {
		return ErrInvalidAlgorithm
	}
	typ, ok := token.Header["typ"]
	if !ok {
		return ErrInvalidHeader
	}
	if typ != token.Context.Type() {
		return ErrInvalidType
	}
	if !token.Valid() {
		return ErrInvalidToken
	}
	return nil
}

func (token *Token) Encode() (string, error) {
	if token.Context == nil {
		return "", ErrContextNotSet
	}
	if token.Header == nil {
		return "", ErrInvalidHeader
	}
	if err := token.Validate(); err != nil {
		return "", err
	}
	return token.encode()
}

func (token *Token) VerifySignature(tokenStr string) error {
	if token.Context == nil {
		return ErrContextNotSet
	}
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
	if token.Context == nil {
		return ErrContextNotSet
	}
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
	if token.Header == nil {
		token.Header = make(map[string]interface{})
	}
	err = decodeBase64JSON(encodedHeader, &token.Header)
	if err != nil {
		return err
	}
	// Decode payload
	if token.Payload == nil {
		token.Payload = make(map[string]interface{})
	}
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

func (token *Token) encode() (tokenString string, err error) {
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
