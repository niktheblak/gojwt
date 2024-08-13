package base64json

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
)

var Encoding = base64.RawURLEncoding

func Decode(data string, v interface{}) error {
	if data == "" {
		return nil
	}
	buf := bytes.NewBufferString(data)
	base64Dec := base64.NewDecoder(Encoding, buf)
	jsonDec := json.NewDecoder(base64Dec)
	return jsonDec.Decode(v)
}

func Encode(v interface{}, w io.Writer) (err error) {
	base64Enc := base64.NewEncoder(Encoding, w)
	jsonEnc := json.NewEncoder(base64Enc)
	err = jsonEnc.Encode(v)
	if err != nil {
		return
	}
	err = base64Enc.Close()
	return
}

func EncodeBase64(data []byte, w io.Writer) (n int, err error) {
	base64Enc := base64.NewEncoder(Encoding, w)
	n, err = base64Enc.Write(data)
	if err != nil {
		return
	}
	err = base64Enc.Close()
	return
}
