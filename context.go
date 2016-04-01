package jwt

type Context struct {
	secret []byte
}

func NewContext(secret []byte) *Context {
	return &Context{secret}
}

func (ctx *Context) Encode(token JSONWebToken) ([]byte, error) {
	return token.Encode(ctx.secret)
}

func (ctx *Context) Decode(data []byte) (JSONWebToken, error) {
	return Decode(ctx.secret, data)
}
