package jwt

import (
	"encoding/base64"

	"github.com/niktheblak/jwt/sign"
)

type Context interface {
	Type() string
	Encoding() *base64.Encoding
	Signer() sign.Signer
	New() *Token
	NewWithClaims(claims map[string]interface{}) *Token
	NewWithHeaderAndClaims(header, claims map[string]interface{}) *Token
}

type defaultContext struct {
	tokenType string
	encoding  *base64.Encoding
	signer    sign.Signer
}

func DefaultContext(secret []byte) Context {
	return &defaultContext{
		tokenType: "JWT",
		encoding:  base64.RawURLEncoding,
		signer:    sign.HS256(secret),
	}
}

func ContextWithSigner(s sign.Signer) Context {
	return &defaultContext{
		tokenType: "JWT",
		encoding:  base64.RawURLEncoding,
		signer:    s,
	}
}

func (c *defaultContext) Type() string {
	return c.tokenType
}

func (c *defaultContext) Encoding() *base64.Encoding {
	return c.encoding
}

func (c *defaultContext) Signer() sign.Signer {
	return c.signer
}

func (c *defaultContext) New() *Token {
	return &Token{
		Context: c,
		Header:  c.createHeader(),
		Claims:  make(map[string]interface{}),
	}
}

func (c *defaultContext) NewWithClaims(claims map[string]interface{}) *Token {
	return &Token{
		Context: c,
		Header:  c.createHeader(),
		Claims:  claims,
	}
}

func (c *defaultContext) NewWithHeaderAndClaims(header, claims map[string]interface{}) *Token {
	if c.signer.Algorithm() != header["alg"] {
		panic("Algorithm used with signer does not match the one given in header")
	}
	return &Token{
		Context: c,
		Header:  header,
		Claims:  claims,
	}
}

func (c *defaultContext) createHeader() map[string]interface{} {
	header := make(map[string]interface{})
	header["typ"] = c.tokenType
	header["alg"] = c.signer.Algorithm()
	return header
}
