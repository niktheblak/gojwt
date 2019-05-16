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
	"math"
	"strings"
	"time"

	"github.com/niktheblak/gojwt/pkg/base64json"
	"github.com/niktheblak/gojwt/pkg/tokencontext"
)

var Encoding = base64.RawURLEncoding

var timestampFields = []string{"exp", "nbf", "iat"}

type Token struct {
	Context tokencontext.Context   `json:"-"`
	Header  map[string]interface{} `json:"header,omitempty"`
	Payload map[string]interface{} `json:"payload,omitempty"`
}

func NewToken(ctx tokencontext.Context) *Token {
	return &Token{
		Context: ctx,
		Header:  ctx.CreateHeader(),
		Payload: make(map[string]interface{}),
	}
}

func Decode(ctx tokencontext.Context, str string) (*Token, error) {
	t := NewToken(ctx)
	err := t.Decode(str)
	if err != nil {
		return nil, err
	}
	return t, nil
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
	alg, ok := token.Header["alg"]
	if !ok {
		// Token must have the algorithm header set
		return ErrInvalidHeader
	}
	if alg != token.Context.Signer().Algorithm() {
		// Token signing algorithm must match the one used in token context
		return ErrInvalidAlgorithm
	}
	typ, ok := token.Header["typ"]
	if !ok {
		// Token must have the type header set
		return ErrInvalidHeader
	}
	if typ != token.Context.Type() {
		// Token type must match the one used in token context
		return ErrInvalidType
	}
	if !token.Valid() {
		// Token must be within it's defined validity period
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
	if err := token.Context.Signer().Verify(encodedContent, signature); err != nil {
		return err
	}
	// Decode header
	if token.Header == nil {
		token.Header = make(map[string]interface{})
	}
	if err := base64json.Decode(encodedHeader, &token.Header); err != nil {
		return err
	}
	// Decode payload
	if token.Payload == nil {
		token.Payload = make(map[string]interface{})
	}
	if err := base64json.Decode(encodedPayload, &token.Payload); err != nil {
		return err
	}
	if err := token.convertTimestamps(); err != nil {
		return err
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

func (token *Token) encode() (tokenString string, err error) {
	buf := new(bytes.Buffer)
	if err = base64json.Encode(token.Header, buf); err != nil {
		return
	}
	err = buf.WriteByte('.')
	if err != nil {
		return
	}
	if err = base64json.Encode(token.Payload, buf); err != nil {
		return
	}
	signature := token.Context.Signer().Sign(buf.String())
	err = buf.WriteByte('.')
	if err != nil {
		return
	}
	if err = base64json.EncodeBase64(signature, buf); err != nil {
		return
	}
	tokenString = buf.String()
	return
}

func (token *Token) convertTimestamps() error {
	for _, f := range timestampFields {
		rawTS, ok := token.Payload[f]
		if ok {
			// json.Unmarshal decodes numbers to float64 if the target type is map[string]interface{}.
			floatTS, ok := rawTS.(float64)
			if ok {
				if math.Floor(floatTS) != floatTS {
					// The timestamp contains decimals which means it's invalid or decoded incorrectly
					return ErrInvalidTimestamp
				}
				token.Payload[f] = int64(floatTS)
			} else {
				return ErrInvalidTimestamp
			}
		}
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
