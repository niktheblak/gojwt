package jwt

import (
	"testing"
	"time"

	"github.com/niktheblak/jwt/errors"
	"github.com/niktheblak/jwt/sign"
	"github.com/stretchr/testify/assert"
)

var (
	testSecret = []byte("secret")
	testSigner = sign.HS256(testSecret)
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

func init() {
	SetDefaultSigner(testSigner)
}

func TestCustomTokenHeader(t *testing.T) {
	token := New()
	token.Header["vendor"] = "ntb"
	token.Claims = testClaims
	tokenStr, err := token.Encode()
	assert.NoError(t, err)
	err = token.Decode(tokenStr)
	assert.NoError(t, err)
	assert.Equal(t, "ntb", token.Header["vendor"])
}

func TestUnsupportedAlgorithm(t *testing.T) {
	header := map[string]interface{}{
		"alg": "XX666",
		"typ": "JWT",
	}
	token := &Token{
		Signer: testSigner,
		Header: header,
		Claims: testClaims,
	}
	tokenStr, err := token.Encode()
	assert.NoError(t, err)
	err = token.Decode(tokenStr)
	assert.EqualError(t, err, errors.ErrInvalidAlgorithm.Error())
}

func TestEncode(t *testing.T) {
	token := NewWithHeaderAndClaims(testHeader, testClaims)
	encoded, err := token.Encode()
	assert.NoError(t, err)
	assert.Equal(t, testToken, encoded)
}

func TestDecode(t *testing.T) {
	token := New()
	err := token.Decode(testToken)
	assert.NoError(t, err)
	assert.Equal(t, testClaims, token.Claims)
}

func BenchmarkEncode(b *testing.B) {
	for i := 0; i < b.N; i++ {
		token := Token{
			Signer: testSigner,
			Header: testHeader,
			Claims: testClaims,
		}
		token.Encode()
	}
}

func BenchmarkDecode(b *testing.B) {
	for i := 0; i < b.N; i++ {
		token := Token{
			Signer: testSigner,
		}
		token.Decode(testToken)
	}
}

func TestRoundTrip(t *testing.T) {
	token := NewWithClaims(testClaims)
	encoded, err := token.Encode()
	assert.NoError(t, err)
	decoded := New()
	err = decoded.Decode(encoded)
	assert.NoError(t, err)
	assert.Equal(t, token.Header, decoded.Header)
	assert.Equal(t, token.Claims, decoded.Claims)
}

func TestSignature(t *testing.T) {
	token := NewWithHeaderAndClaims(testHeader, testClaims)
	encoded, err := token.Encode()
	assert.NoError(t, err)
	err = token.VerifySignature(encoded)
	assert.NoError(t, err)
}

func TestExpiredToken(t *testing.T) {
	token := New()
	ts := time.Now().Add(time.Hour * -1)
	token.SetExpiration(ts)
	encoded, err := token.Encode()
	assert.NoError(t, err)
	decoded := New()
	err = decoded.Decode(encoded)
	assert.EqualError(t, err, errors.ErrExpiredToken.Error())
}
