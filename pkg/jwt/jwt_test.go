package jwt

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/niktheblak/gojwt/pkg/tokencontext"
)

var (
	testSecret  = []byte("secret")
	testContext = tokencontext.DefaultContext(testSecret)
	testHeader  = map[string]interface{}{
		"alg": testContext.Signer().Algorithm(),
		"typ": testContext.Type(),
	}
	testClaims = map[string]interface{}{
		"sub":   "1234567890",
		"name":  "John Doe",
		"admin": true,
		"iat":   time.Now().Unix(),
		"exp":   time.Now().Add(time.Hour).Unix(),
	}
)

func TestCustomTokenHeader(t *testing.T) {
	token := NewToken(testContext)
	token.Header["vendor"] = "ntb"
	token.Payload = testClaims
	tokenStr, err := token.Encode()
	require.NoError(t, err)
	decoded, err := Decode(testContext, tokenStr)
	require.NoError(t, err)
	assert.Equal(t, "ntb", decoded.Header["vendor"])
}

func TestUnsupportedAlgorithm(t *testing.T) {
	// Tests for for the attack described in
	// https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/
	header := map[string]interface{}{
		"alg": "none",
		"typ": "JWT",
	}
	token := &Token{
		Context: testContext,
		Header:  header,
		Payload: testClaims,
	}
	tokenStr, err := token.encode()
	require.NoError(t, err)
	_, err = Decode(testContext, tokenStr)
	assert.EqualError(t, err, ErrInvalidAlgorithm.Error())
}

func BenchmarkEncode(b *testing.B) {
	token := &Token{
		Context: testContext,
		Header:  testHeader,
		Payload: testClaims,
	}
	for i := 0; i < b.N; i++ {
		_, err := token.Encode()
		if err != nil {
			b.Fail()
		}
	}
}

func BenchmarkDecode(b *testing.B) {
	token := NewToken(testContext)
	token.Header = testHeader
	token.Payload = testClaims
	encoded, err := token.Encode()
	if err != nil {
		b.FailNow()
	}
	for i := 0; i < b.N; i++ {
		_, err := Decode(testContext, encoded)
		if err != nil {
			b.Fail()
		}
	}
}

func TestRoundTrip(t *testing.T) {
	token := NewToken(testContext)
	token.Payload = testClaims
	encoded, err := token.Encode()
	require.NoError(t, err)
	decoded, err := Decode(testContext, encoded)
	require.NoError(t, err)
	assert.Equal(t, token.Header, decoded.Header)
	assert.Equal(t, token.Payload, decoded.Payload)
}

func TestSignature(t *testing.T) {
	token := NewToken(testContext)
	token.Header = testHeader
	token.Payload = testClaims
	encoded, err := token.Encode()
	require.NoError(t, err)
	err = token.VerifySignature(encoded)
	require.NoError(t, err)
}

func TestExpiration(t *testing.T) {
	token := NewToken(testContext)
	token.SetExpiration(time.Now().Add(-time.Hour))
	encoded, err := token.encode()
	require.NoError(t, err)
	_, err = Decode(testContext, encoded)
	assert.EqualError(t, err, ErrInvalidToken.Error())
}

func TestNotBefore(t *testing.T) {
	token := NewToken(testContext)
	token.SetNotBefore(time.Now().Add(time.Hour))
	encoded, err := token.encode()
	require.NoError(t, err)
	_, err = Decode(testContext, encoded)
	assert.EqualError(t, err, ErrInvalidToken.Error())
}

func TestTokenWithoutContext(t *testing.T) {
	token := new(Token)
	t.Run("ValidateWithoutContext", func(t *testing.T) {
		err := token.Validate()
		assert.EqualError(t, err, ErrContextNotSet.Error())
	})
	t.Run("EncodeWithoutContext", func(t *testing.T) {
		_, err := token.Encode()
		assert.EqualError(t, err, ErrContextNotSet.Error())
	})
	t.Run("DecodeWithoutContext", func(t *testing.T) {
		err := token.Decode("notvalidtoken")
		assert.EqualError(t, err, ErrContextNotSet.Error())
	})
}
