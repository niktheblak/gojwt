package jwt

import (
	"github.com/niktheblak/jwt/encoder"
	"github.com/niktheblak/jwt/errors"
	"github.com/niktheblak/jwt/sign"
	"github.com/niktheblak/jwt/sign/hs256"
)

var SupportedAlgorithms = map[sign.Algorithm]bool{
	sign.AlgoHS256: true,
}

type JWTConfig struct {
	Signer sign.Signer
	Header map[string]interface{}
}

type JWTContext struct {
	config JWTConfig
	header map[string]interface{}
}

func NewContext(secret []byte) *JWTContext {
	return NewContextWithConfig(JWTConfig{
		Signer: hs256.New(secret),
		Header: nil,
	})
}

func NewContextWithConfig(config JWTConfig) *JWTContext {
	algo := config.Signer.Algorithm()
	if !SupportedAlgorithms[algo] {
		panic("Unsupported algorithm: " + algo.String())
	}
	header := make(map[string]interface{})
	for k, v := range config.Header {
		header[k] = v
	}
	header["alg"] = sign.AlgorithmNames[algo]
	header["typ"] = "JWT"
	return &JWTContext{
		config: config,
		header: header,
	}
}

func (ctx *JWTContext) Encode(token JSONWebToken) (string, error) {
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

func (ctx *JWTContext) Decode(tokenStr string) (JSONWebToken, error) {
	token, err := encoder.Decode(ctx.config.Signer, tokenStr)
	if err != nil {
		return JSONWebToken{}, err
	}
	jwt := fromToken(token)
	err = ctx.Validate(jwt)
	return jwt, err
}

func (ctx *JWTContext) Validate(token JSONWebToken) error {
	if token.Algorithm() != ctx.config.Signer.Algorithm() {
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

func (ctx *JWTContext) mergeHeaders(token JSONWebToken) map[string]interface{} {
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
