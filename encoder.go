package jwt

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"
)

var encoding = base64.RawURLEncoding

func (token JSONWebToken) Encode(secret []byte) (string, error) {
	var buf bytes.Buffer
	encoder := base64.NewEncoder(encoding, &buf)
	header, err := json.Marshal(token.header)
	if err != nil {
		return "", err
	}
	encoder.Write(header)
	buf.WriteByte('.')
	claims, err := json.Marshal(token.Claims)
	if err != nil {
		return "", err
	}
	encoder.Write(claims)
	signature := Sign(secret, buf.String())
	buf.WriteByte('.')
	encoder.Write(signature)
	encoder.Close()
	return buf.String(), nil
}

func Decode(secret []byte, tokenStr string) (token JSONWebToken, err error) {
	claimsPos := strings.IndexByte(tokenStr, '.')
	if claimsPos == -1 {
		err = ErrMalformedToken
		return
	}
	signaturePos := strings.LastIndexByte(tokenStr, '.')
	if signaturePos == claimsPos {
		err = ErrMalformedToken
		return
	}
	payloadStr := tokenStr[:signaturePos]
	headerStr := tokenStr[:claimsPos]
	claimsStr := tokenStr[claimsPos+1 : signaturePos]
	signatureStr := tokenStr[signaturePos+1:]
	// Verify signature
	rawSignature, err := encoding.DecodeString(signatureStr)
	if err != nil {
		return
	}
	err = Verify(secret, payloadStr, rawSignature)
	if err != nil {
		return
	}
	// Decode header
	token.header = make(map[string]string)
	err = decodeBase64JSON(headerStr, &token.header)
	if err != nil {
		return
	}
	// Decode claims
	token.Claims = make(map[string]interface{})
	err = decodeBase64JSON(claimsStr, &token.Claims)
	if err != nil {
		return
	}
	err = token.Validate()
	return
}

func VerifySignature(secret []byte, tokenStr string) error {
	signaturePos := strings.LastIndexByte(tokenStr, '.')
	if signaturePos == -1 {
		return ErrMalformedToken
	}
	payloadBytes := tokenStr[:signaturePos]
	signatureBytes := tokenStr[signaturePos+1:]
	signature, err := encoding.DecodeString(signatureBytes)
	if err != nil {
		return err
	}
	return Verify(secret, payloadBytes, signature)
}

func decodeBase64JSON(data string, v interface{}) error {
	decoded, err := encoding.DecodeString(data)
	err = json.Unmarshal(decoded, v)
	if err != nil {
		return err
	}
	return nil
}
