package jwt

type Context struct {
	secret []byte
}

func NewContext(secret []byte) *Context {
	return &Context{secret}
}

func (ctx *Context) Encode(token JSONWebToken) (string, error) {
	return token.Encode(ctx.secret)
}

func (ctx *Context) Decode(tokenStr string) (JSONWebToken, error) {
	return Decode(ctx.secret, tokenStr)
}
