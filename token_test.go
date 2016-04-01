package jwt

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCustomHeader(t *testing.T) {
	token := New()
	token.SetHeader("vendor", "ntb")
	token.Claims = testClaims
	_, err := token.Encode(testSecret)
	assert.NoError(t, err)
}
