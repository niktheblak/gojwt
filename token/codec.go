package token

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
)

func decodeBase64JSON(data string, v interface{}) error {
	if data == "" {
		return nil
	}
	buf := bytes.NewBufferString(data)
	base64Dec := base64.NewDecoder(encoding, buf)
	jsonDec := json.NewDecoder(base64Dec)
	return jsonDec.Decode(v)
}

func encodeBase64JSON(v interface{}, w io.Writer) error {
	base64Enc := base64.NewEncoder(encoding, w)
	jsonEnc := json.NewEncoder(base64Enc)
	err := jsonEnc.Encode(v)
	if err != nil {
		return err
	}
	return base64Enc.Close()
}

func encodeBase64(data []byte, w io.Writer) error {
	base64Enc := base64.NewEncoder(encoding, w)
	_, err := base64Enc.Write(data)
	if err != nil {
		return err
	}
	return base64Enc.Close()
}
