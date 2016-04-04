package jwt

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCustomHeader(t *testing.T) {
	ctx := NewContext(testSecret)
	token := New()
	token.SetHeader("vendor", "ntb")
	token.Claims = testClaims
	_, err := ctx.Encode(token)
	assert.NoError(t, err)
}
