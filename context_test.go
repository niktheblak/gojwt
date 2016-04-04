package jwt

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

var testSecret = []byte("secret")

var testClaims = map[string]interface{}{
	"sub":   "1234567890",
	"name":  "John Doe",
	"admin": true,
}

func TestCustomHeader(t *testing.T) {
	ctx := NewContext(testSecret)
	token := New()
	token.SetHeader("vendor", "ntb")
	token.Claims = testClaims
	tokenStr, err := ctx.Encode(token)
	assert.NoError(t, err)
	decoded, err := ctx.Decode(tokenStr)
	assert.NoError(t, err)
	assert.Equal(t, "ntb", decoded.Header("vendor"))
}
