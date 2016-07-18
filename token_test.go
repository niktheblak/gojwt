package jwt

import (
	"testing"
	"time"

	"github.com/niktheblak/jwt/sign"
	"github.com/stretchr/testify/assert"
)

var (
	testSecret  = []byte("secret")
	testSigner  = sign.HS256(testSecret)
	testContext = ContextWithSigner(testSigner)
	testHeader  = map[string]interface{}{
		"alg": testSigner.Algorithm(),
		"typ": testContext.Type(),
	}
	testClaims = map[string]interface{}{
		"sub":   "1234567890",
		"name":  "John Doe",
		"admin": true,
	}
	testToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhZG1pbiI6dHJ1ZSwibmFtZSI6IkpvaG4gRG9lIiwic3ViIjoiMTIzNDU2Nzg5MCJ9.eNK_fimsCW3Q-meOXyc_dnZHubl2D4eZkIcn6llniCk"
)

func TestCustomTokenHeader(t *testing.T) {
	token := testContext.New()
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
		Context: testContext,
		Header:  header,
		Claims:  testClaims,
	}
	tokenStr, err := token.Encode()
	assert.NoError(t, err)
	err = token.Decode(tokenStr)
	assert.EqualError(t, err, ErrInvalidAlgorithm.Error())
}

func TestEncode(t *testing.T) {
	token := testContext.NewWithHeaderAndClaims(testHeader, testClaims)
	encoded, err := token.Encode()
	assert.NoError(t, err)
	assert.Equal(t, testToken, encoded)
}

func TestDecode(t *testing.T) {
	token := testContext.New()
	err := token.Decode(testToken)
	assert.NoError(t, err)
	assert.Equal(t, testClaims, token.Claims)
}

func BenchmarkEncode(b *testing.B) {
	for i := 0; i < b.N; i++ {
		token := &Token{
			Context: testContext,
			Header:  testHeader,
			Claims:  testClaims,
		}
		token.Encode()
	}
}

func BenchmarkDecode(b *testing.B) {
	for i := 0; i < b.N; i++ {
		token := &Token{
			Context: testContext,
		}
		token.Decode(testToken)
	}
}

func TestRoundTrip(t *testing.T) {
	token := testContext.NewWithClaims(testClaims)
	encoded, err := token.Encode()
	assert.NoError(t, err)
	decoded := testContext.New()
	err = decoded.Decode(encoded)
	assert.NoError(t, err)
	assert.Equal(t, token.Header, decoded.Header)
	assert.Equal(t, token.Claims, decoded.Claims)
}

func TestSignature(t *testing.T) {
	token := testContext.NewWithHeaderAndClaims(testHeader, testClaims)
	encoded, err := token.Encode()
	assert.NoError(t, err)
	err = token.VerifySignature(encoded)
	assert.NoError(t, err)
}

func TestExpiredToken(t *testing.T) {
	token := testContext.New()
	ts := time.Now().Add(time.Hour * -1)
	token.SetExpiration(ts)
	encoded, err := token.Encode()
	assert.NoError(t, err)
	decoded := testContext.New()
	err = decoded.Decode(encoded)
	assert.EqualError(t, err, ErrExpiredToken.Error())
}
