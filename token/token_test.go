package token

import (
	"testing"
	"time"

	"github.com/niktheblak/gojwt/sign"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
)

func TestCustomTokenHeader(t *testing.T) {
	token := testContext.NewToken()
	token.Header["vendor"] = "ntb"
	token.Payload = testClaims
	tokenStr, err := token.Encode()
	require.NoError(t, err)
	decoded, err := testContext.Decode(tokenStr)
	require.NoError(t, err)
	assert.Equal(t, "ntb", decoded.Header["vendor"])
}

func TestUnsupportedAlgorithm(t *testing.T) {
	header := map[string]interface{}{
		"alg": "XX666",
		"typ": "JWT",
	}
	token := &Token{
		Context: testContext,
		Header:  header,
		Payload: testClaims,
	}
	tokenStr, err := token.Encode()
	require.NoError(t, err)
	_, err = testContext.Decode(tokenStr)
	assert.EqualError(t, err, ErrInvalidAlgorithm.Error())
}

func BenchmarkEncode(b *testing.B) {
	token := &Token{
		Context: testContext,
		Header:  testHeader,
		Payload: testClaims,
	}
	token.AddClaim("exp", time.Now().Add(1*time.Hour).Unix())
	for i := 0; i < b.N; i++ {
		_, err := token.Encode()
		if err != nil {
			b.Fail()
		}
	}
}

func BenchmarkDecode(b *testing.B) {
	token := testContext.NewToken()
	token.Header = testHeader
	token.Payload = testClaims
	token.AddClaim("exp", time.Now().Add(1*time.Hour).Unix())
	encoded, err := token.Encode()
	if err != nil {
		b.FailNow()
	}
	for i := 0; i < b.N; i++ {
		_, err := testContext.Decode(encoded)
		if err != nil {
			b.Fail()
		}
	}
}

func TestRoundTrip(t *testing.T) {
	token := testContext.NewToken()
	token.Payload = testClaims
	encoded, err := token.Encode()
	require.NoError(t, err)
	decoded, err := testContext.Decode(encoded)
	require.NoError(t, err)
	assert.Equal(t, token.Header, decoded.Header)
	assert.Equal(t, token.Payload, decoded.Payload)
}

func TestSignature(t *testing.T) {
	token := testContext.NewToken()
	token.Header = testHeader
	token.Payload = testClaims
	encoded, err := token.Encode()
	require.NoError(t, err)
	err = token.VerifySignature(encoded)
	require.NoError(t, err)
}

func TestExpiredToken(t *testing.T) {
	token := testContext.NewToken()
	ts := time.Now().Add(time.Hour * -1)
	token.SetExpiration(ts)
	encoded, err := token.Encode()
	require.NoError(t, err)
	_, err = testContext.Decode(encoded)
	assert.EqualError(t, err, ErrExpiredToken.Error())
}
