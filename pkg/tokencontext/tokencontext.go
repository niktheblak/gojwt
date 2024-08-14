package tokencontext

import (
	"github.com/niktheblak/gojwt/pkg/sign"
	"github.com/niktheblak/gojwt/pkg/sign/sha"
)

type Context interface {
	Type() string
	Signer() sign.Signer
	CreateHeader() map[string]interface{}
}

type context struct {
	tokenType string
	signer    sign.Signer
}

func Default(secret []byte) Context {
	return &context{
		tokenType: "JWT",
		signer:    sha.HS256(secret),
	}
}

func ContextWithSigner(signer sign.Signer) Context {
	return &context{
		tokenType: "JWT",
		signer:    signer,
	}
}

func (c *context) Type() string {
	return c.tokenType
}

func (c *context) Signer() sign.Signer {
	return c.signer
}

func (c *context) CreateHeader() map[string]interface{} {
	header := make(map[string]interface{})
	header["typ"] = c.tokenType
	header["alg"] = c.signer.Algorithm()
	return header
}
