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

var testToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhZG1pbiI6dHJ1ZSwibmFtZSI6IkpvaG4gRG9lIiwic3ViIjoiMTIzNDU2Nzg5MCJ9.eNK_fimsCW3Q-meOXyc_dnZHubl2D4eZkIcn6llniCk"

func TestEncode(t *testing.T) {
	token := New()
	token.Claims = testClaims
	encoded, err := token.Encode(testSecret)
	assert.Equal(t, testToken, string(encoded))
	assert.NoError(t, err)
}

func TestDecode(t *testing.T) {
	token, err := Decode(testSecret, []byte(testToken))
	assert.NoError(t, err)
	assert.Equal(t, testClaims, token.Claims)
}

func TestSignature(t *testing.T) {
	token := New()
	token.Claims = testClaims
	encoded, err := token.Encode(testSecret)
	assert.NoError(t, err)
	err = VerifySignature(testSecret, encoded)
	assert.NoError(t, err)
}
