package jwt

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/niktheblak/gojwt/pkg/base64json"
	"github.com/niktheblak/gojwt/pkg/sign"
	"github.com/niktheblak/gojwt/pkg/tokencontext"
)

var timestampFields = []string{"exp", "nbf", "iat"}

type Token struct {
	Context tokencontext.Context `json:"-"`
	Header  map[string]any       `json:"header,omitempty"`
	Payload map[string]any       `json:"payload,omitempty"`
}

func NewToken(ctx tokencontext.Context) *Token {
	return &Token{
		Context: ctx,
		Header:  ctx.CreateHeader(),
		Payload: make(map[string]any),
	}
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
		return fmt.Errorf("%w: missing alg field", ErrInvalidHeader)
	}
	algStr, ok := alg.(string)
	if !ok {
		return fmt.Errorf("%w: alg field is not a string", ErrInvalidHeader)
	}
	algorithm, err := sign.ParseAlgorithm(algStr)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidHeader, err)
	}
	if algorithm != token.Context.Signer().Algorithm() {
		return ErrInvalidAlgorithm
	}
	typ, ok := token.Header["typ"]
	if !ok {
		return fmt.Errorf("%w: missing typ field", ErrInvalidHeader)
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
	signature, err := base64json.Encoding.DecodeString(encodedSignature)
	if err != nil {
		return err
	}
	var tokenErrs []error
	if err := token.Context.Signer().Verify(encodedContent, signature); err != nil {
		tokenErrs = append(tokenErrs, err)
	}
	// Decode header
	if token.Header == nil {
		token.Header = make(map[string]any)
	}
	if err := base64json.Decode(encodedHeader, &token.Header); err != nil {
		return err
	}
	// Decode payload
	if token.Payload == nil {
		token.Payload = make(map[string]any)
	}
	if err := base64json.Decode(encodedPayload, &token.Payload); err != nil {
		return err
	}
	if err := token.convertTimestamps(); err != nil {
		return err
	}
	if err := token.Validate(); err != nil {
		tokenErrs = append(tokenErrs, err)
	}
	return errors.Join(tokenErrs...)
}

func (token *Token) String() string {
	buf := new(bytes.Buffer)
	enc := json.NewEncoder(buf)
	enc.SetIndent("", "    ")
	if err := enc.Encode(token); err != nil {
		panic(err)
	}
	return buf.String()
}

func (token *Token) encode() (tokenStr string, err error) {
	buf := new(bytes.Buffer)
	if err = base64json.Encode(token.Header, buf); err != nil {
		return
	}
	if err = buf.WriteByte('.'); err != nil {
		return
	}
	if err = base64json.Encode(token.Payload, buf); err != nil {
		return
	}
	signature, err := token.Context.Signer().Sign(buf.String())
	if err != nil {
		return
	}
	if err = buf.WriteByte('.'); err != nil {
		return
	}
	if _, err = base64json.EncodeBase64(signature, buf); err != nil {
		return
	}
	tokenStr = buf.String()
	return
}

func (token *Token) convertTimestamps() error {
	for _, f := range timestampFields {
		rawTS, ok := token.Payload[f]
		if ok {
			// json.Unmarshal decodes numbers to float64 if the target type is map[string]any.
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

func Decode(ctx tokencontext.Context, str string) (t *Token, err error) {
	t = NewToken(ctx)
	err = t.Decode(str)
	return
}

func optString(m map[string]any, key string) string {
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

func optTimestamp(m map[string]any, key string) (t time.Time, ok bool) {
	rawTS, ok := m[key]
	if !ok {
		return
	}
	ts, ok := rawTS.(int64)
	if !ok {
		return
	}
	t = time.Unix(ts, 0)
	ok = true
	return
}
