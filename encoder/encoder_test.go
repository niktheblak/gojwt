package encoder

import (
	"testing"

	"github.com/niktheblak/jwt/sign"
	"github.com/niktheblak/jwt/sign/algorithm"
	"github.com/stretchr/testify/assert"
)

var (
	testSecret = []byte("secret")
	testAlgo   = algorithm.HS256()
	testSigner = sign.New(testAlgo, testSecret)
	testHeader = map[string]interface{}{
		"alg": "HS256",
		"typ": "JWT",
	}
	testClaims = map[string]interface{}{
		"sub":   "1234567890",
		"name":  "John Doe",
		"admin": true,
	}
	testToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhZG1pbiI6dHJ1ZSwibmFtZSI6IkpvaG4gRG9lIiwic3ViIjoiMTIzNDU2Nzg5MCJ9.eNK_fimsCW3Q-meOXyc_dnZHubl2D4eZkIcn6llniCk"
)

func TestEncode(t *testing.T) {
	token := Token{
		Header: testHeader,
		Claims: testClaims,
	}
	encoded, err := Encode(testSigner, token)
	assert.NoError(t, err)
	assert.Equal(t, testToken, encoded)
}

func TestDecode(t *testing.T) {
	token, err := Decode(testSigner, testToken)
	assert.NoError(t, err)
	assert.Equal(t, testClaims, token.Claims)
}

func TestRoundTrip(t *testing.T) {
	token := Token{
		Header: testHeader,
		Claims: testClaims,
	}
	encoded, err := Encode(testSigner, token)
	assert.NoError(t, err)
	decoded, err := Decode(testSigner, encoded)
	assert.NoError(t, err)
	assert.Equal(t, token, decoded)
}

func TestSignature(t *testing.T) {
	token := Token{
		Header: testHeader,
		Claims: testClaims,
	}
	encoded, err := Encode(testSigner, token)
	assert.NoError(t, err)
	err = VerifySignature(testSigner, encoded)
	assert.NoError(t, err)
}
