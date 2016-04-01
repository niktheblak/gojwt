package jwt

var DefaultHeader = map[string]string{
	"alg": "HS256",
	"typ": "JWT",
}

type JSONWebToken struct {
	header map[string]string
	Claims map[string]interface{}
}

func New() JSONWebToken {
	return JSONWebToken{
		header: DefaultHeader,
		Claims: make(map[string]interface{}),
	}
}

func (t JSONWebToken) Headers() []string {
	var keys []string
	for k := range t.header {
		keys = append(keys, k)
	}
	return keys
}

func (t JSONWebToken) Header(key string) string {
	return t.header[key]
}

func (t JSONWebToken) SetHeader(key, value string) {
	if &t.header == &DefaultHeader {
		hdr := make(map[string]string)
		for k, v := range t.header {
			hdr[k] = v
		}
		t.header = hdr
	}
	t.header[key] = value
}
