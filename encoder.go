package jwt

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
)

var encoding = base64.RawURLEncoding

func (token JSONWebToken) Encode(secret []byte) ([]byte, error) {
	err := token.Validate()
	if err != nil {
		return nil, err
	}
	buf := new(bytes.Buffer)
	encoder := base64.NewEncoder(encoding, buf)
	header, err := json.Marshal(token.header)
	if err != nil {
		return nil, err
	}
	encoder.Write(header)
	buf.WriteByte('.')
	claims, err := json.Marshal(token.Claims)
	if err != nil {
		return nil, err
	}
	encoder.Write(claims)
	signature := Sign(secret, buf.Bytes())
	buf.WriteByte('.')
	encoder.Write(signature)
	encoder.Close()
	data := make([]byte, len(buf.Bytes()))
	copy(data, buf.Bytes())
	return data, nil
}

func Decode(secret, data []byte) (token JSONWebToken, err error) {
	claimsPos := bytes.IndexByte(data, '.')
	if claimsPos == -1 {
		err = ErrMalformedToken
		return
	}
	signaturePos := bytes.LastIndexByte(data, '.')
	if signaturePos == claimsPos {
		err = ErrMalformedToken
		return
	}
	payloadBytes := data[:signaturePos]
	headerBytes := data[:claimsPos]
	claimsBytes := data[claimsPos+1 : signaturePos]
	signatureBytes := data[signaturePos+1:]
	// Verify signature
	rawSignature, err := decodeBase64(signatureBytes)
	if err != nil {
		return
	}
	err = Verify(secret, payloadBytes, rawSignature)
	if err != nil {
		return
	}
	// Decode header
	token.header = make(map[string]string)
	err = decodeBase64JSON(headerBytes, &token.header)
	if err != nil {
		return
	}
	// Decode claims
	token.Claims = make(map[string]interface{})
	err = decodeBase64JSON(claimsBytes, &token.Claims)
	if err != nil {
		return
	}
	err = token.Validate()
	return
}

func VerifySignature(secret, data []byte) error {
	signaturePos := bytes.LastIndexByte(data, '.')
	if signaturePos == -1 {
		return ErrMalformedToken
	}
	payloadBytes := data[:signaturePos]
	signatureBytes := data[signaturePos+1:]
	decoded := make([]byte, len(signatureBytes))
	n, err := encoding.Decode(decoded, signatureBytes)
	if err != nil {
		return err
	}
	signature := decoded[:n]
	return Verify(secret, payloadBytes, signature)
}

func decodeBase64(data []byte) ([]byte, error) {
	decoded := make([]byte, len(data))
	n, err := encoding.Decode(decoded, data)
	if err != nil {
		return decoded, err
	}
	decoded = decoded[:n]
	return decoded, nil
}

func decodeBase64JSON(data []byte, v interface{}) error {
	buf := bytes.NewBuffer(data)
	base64Decoder := base64.NewDecoder(encoding, buf)
	jsonDecoder := json.NewDecoder(base64Decoder)
	err := jsonDecoder.Decode(v)
	if err != nil {
		return err
	}
	return nil
}
