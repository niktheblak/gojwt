/*
  Copyright 2017 Niko Korhonen

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
 */

package jwt

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
		"iat":   time.Now().Unix(),
		"exp":   time.Now().Add(time.Hour).Unix(),
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

func TestExpiration(t *testing.T) {
	token := testContext.NewToken()
	token.SetExpiration(time.Now().Add(-time.Hour))
	encoded, err := token.Encode()
	require.NoError(t, err)
	_, err = testContext.Decode(encoded)
	assert.EqualError(t, err, ErrExpiredToken.Error())
}

func TestNotBefore(t *testing.T) {
	token := testContext.NewToken()
	token.SetNotBefore(time.Now().Add(time.Hour))
	encoded, err := token.Encode()
	require.NoError(t, err)
	_, err = testContext.Decode(encoded)
	assert.EqualError(t, err, ErrUsedBeforeValidity.Error())
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
