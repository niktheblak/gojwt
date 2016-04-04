package jwt

import (
	"testing"

	"github.com/niktheblak/jwt/encoder"
	"github.com/stretchr/testify/assert"
)

var testSecret = []byte("secret")

var testClaims = map[string]interface{}{
	"sub":   "1234567890",
	"name":  "John Doe",
	"admin": true,
}

var testToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhZG1pbiI6dHJ1ZSwibmFtZSI6IkpvaG4gRG9lIiwic3ViIjoiMTIzNDU2Nzg5MCJ9.eNK_fimsCW3Q-meOXyc_dnZHubl2D4eZkIcn6llniCk"

func TestEncode(t *testing.T) {
	ctx := NewContext(testSecret)
	token := New()
	token.Claims = testClaims
	encoded, err := ctx.Encode(token)
	assert.Equal(t, testToken, string(encoded))
	assert.NoError(t, err)
}

func TestDecode(t *testing.T) {
	ctx := NewContext(testSecret)
	token, err := ctx.Decode(testToken)
	assert.NoError(t, err)
	assert.Equal(t, testClaims, token.Claims)
}

func TestSignature(t *testing.T) {
	ctx := NewContext(testSecret)
	token := New()
	token.Claims = testClaims
	encoded, err := ctx.Encode(token)
	assert.NoError(t, err)
	err = encoder.VerifySignature(testSecret, encoded)
	assert.NoError(t, err)
}
