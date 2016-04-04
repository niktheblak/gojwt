package encoder

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

var testSecret = []byte("secret")

var testHeader = map[string]interface{}{
	"alg": "HS256",
	"typ": "JWT",
}

var testClaims = map[string]interface{}{
	"sub":   "1234567890",
	"name":  "John Doe",
	"admin": true,
}

var testToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhZG1pbiI6dHJ1ZSwibmFtZSI6IkpvaG4gRG9lIiwic3ViIjoiMTIzNDU2Nzg5MCJ9.eNK_fimsCW3Q-meOXyc_dnZHubl2D4eZkIcn6llniCk"

func TestEncode(t *testing.T) {
	token := Token{
		Header: testHeader,
		Claims: testClaims,
	}
	encoded, err := Encode(testSecret, token)
	assert.NoError(t, err)
	assert.Equal(t, testToken, encoded)
}

func TestDecode(t *testing.T) {
	token, err := Decode(testSecret, testToken)
	assert.NoError(t, err)
	assert.Equal(t, testClaims, token.Claims)
}

func TestRoundTrip(t *testing.T) {
	token := Token{
		Header: testHeader,
		Claims: testClaims,
	}
	encoded, err := Encode(testSecret, token)
	assert.NoError(t, err)
	decoded, err := Decode(testSecret, encoded)
	assert.NoError(t, err)
	assert.Equal(t, token, decoded)
}

func TestSignature(t *testing.T) {
	token := Token{
		Header: testHeader,
		Claims: testClaims,
	}
	encoded, err := Encode(testSecret, token)
	assert.NoError(t, err)
	err = VerifySignature(testSecret, encoded)
	assert.NoError(t, err)
}
