package jwt

import (
	"testing"

	"github.com/niktheblak/jwt/encoder"
	"github.com/niktheblak/jwt/errors"
	"github.com/niktheblak/jwt/sign/hs256"
	"github.com/stretchr/testify/assert"
)

var testSecret = []byte("secret")

var testClaims = map[string]interface{}{
	"sub":   "1234567890",
	"name":  "John Doe",
	"admin": true,
}

func TestCustomContextHeader(t *testing.T) {
	contextHeaders := map[string]interface{}{
		"vendor": "ntb",
	}
	ctx := NewContextWithConfig(JWTConfig{
		Signer: hs256.New(testSecret),
		Header: contextHeaders,
	})
	token := New()
	token.Claims = testClaims
	tokenStr, err := ctx.Encode(token)
	assert.NoError(t, err)
	decoded, err := ctx.Decode(tokenStr)
	assert.NoError(t, err)
	assert.Equal(t, "ntb", decoded.Header["vendor"])
}

func TestCustomTokenHeader(t *testing.T) {
	ctx := NewContext(testSecret)
	token := New()
	token.Header = map[string]interface{}{
		"vendor": "ntb",
	}
	token.Claims = testClaims
	tokenStr, err := ctx.Encode(token)
	assert.NoError(t, err)
	decoded, err := ctx.Decode(tokenStr)
	assert.NoError(t, err)
	assert.Equal(t, "ntb", decoded.Header["vendor"])
}

func TestUnsupportedAlgorithm(t *testing.T) {
	signer := hs256.New(testSecret)
	ctx := NewContextWithConfig(JWTConfig{
		Signer: signer,
	})
	header := map[string]interface{}{
		"alg": "XX666",
		"typ": "JWT",
	}
	tokenStr, err := encoder.Encode(signer, encoder.Token{
		Header: header,
		Claims: testClaims,
	})
	assert.NoError(t, err)
	_, err = ctx.Decode(tokenStr)
	assert.EqualError(t, err, errors.ErrInvalidAlgorithm.Error())
}
