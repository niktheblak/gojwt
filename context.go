package jwt

import (
	"github.com/niktheblak/jwt/encoder"
	"github.com/niktheblak/jwt/errors"
	"github.com/niktheblak/jwt/sign"
)

var SupportedAlgorithms = map[string]bool{
	"HS256": true,
}

type Config struct {
	Signer sign.Signer
	Header map[string]interface{}
}

type TokenContext struct {
	config Config
	header map[string]interface{}
}

func NewContext(secret []byte) *TokenContext {
	return NewContextWithConfig(Config{
		Signer: sign.New(sign.HS256(), secret),
		Header: nil,
	})
}

func NewContextWithConfig(config Config) *TokenContext {
	algo := config.Signer.Algorithm()
	if !SupportedAlgorithms[algo.Name] {
		panic("Unsupported algorithm: " + algo.String())
	}
	header := make(map[string]interface{})
	for k, v := range config.Header {
		header[k] = v
	}
	header["alg"] = algo.Name
	header["typ"] = "JWT"
	return &TokenContext{
		config: config,
		header: header,
	}
}

func (ctx *TokenContext) Encode(token JSONWebToken) (string, error) {
	var header map[string]interface{}
	if token.Header == nil {
		header = ctx.header
	} else {
		header = ctx.mergeHeaders(token)
	}
	return encoder.Encode(ctx.config.Signer, encoder.Token{
		Header: header,
		Claims: token.Claims,
	})
}

func (ctx *TokenContext) Decode(tokenStr string) (JSONWebToken, error) {
	token, err := encoder.Decode(ctx.config.Signer, tokenStr)
	if err != nil {
		return JSONWebToken{}, err
	}
	jwt := fromToken(token)
	err = ctx.Validate(jwt)
	return jwt, err
}

func (ctx *TokenContext) Validate(token JSONWebToken) error {
	if token.Algorithm().Name != ctx.config.Signer.Algorithm().Name {
		return errors.ErrInvalidAlgorithm
	}
	if token.Type() != "JWT" {
		return errors.ErrInvalidType
	}
	if token.Expired() {
		return errors.ErrExpiredToken
	}
	return nil
}

func (ctx *TokenContext) mergeHeaders(token JSONWebToken) map[string]interface{} {
	header := make(map[string]interface{})
	for k, v := range ctx.header {
		header[k] = v
	}
	for k, v := range token.Header {
		header[k] = v
	}
	return header
}

func fromToken(token encoder.Token) JSONWebToken {
	return JSONWebToken{
		Header: token.Header,
		Claims: token.Claims,
	}
}
