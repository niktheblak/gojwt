package jwt

import "github.com/niktheblak/jwt/encoder"

type JWTContext struct {
	secret []byte
}

func NewContext(secret []byte) *JWTContext {
	return &JWTContext{secret}
}

func (ctx *JWTContext) Encode(token JSONWebToken) (string, error) {
	return encoder.Encode(ctx.secret, encoder.Token{
		Header: token.header,
		Claims: token.Claims,
	})
}

func (ctx *JWTContext) Decode(tokenStr string) (JSONWebToken, error) {
	token, err := encoder.Decode(ctx.secret, tokenStr)
	return JSONWebToken{
		header: token.Header,
		Claims: token.Claims,
	}, err
}
