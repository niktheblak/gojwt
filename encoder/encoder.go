package encoder

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"

	"github.com/niktheblak/jwt/errors"
	sig "github.com/niktheblak/jwt/signature"
)

type Token struct {
	Header map[string]interface{}
	Claims map[string]interface{}
}

var DefaultEncoding = base64.RawURLEncoding

func Encode(secret []byte, token Token) (string, error) {
	var buf bytes.Buffer
	encoder := base64.NewEncoder(DefaultEncoding, &buf)
	headerJSON, err := json.Marshal(token.Header)
	if err != nil {
		return "", err
	}
	encoder.Write(headerJSON)
	buf.WriteByte('.')
	claimsJSON, err := json.Marshal(token.Claims)
	if err != nil {
		return "", err
	}
	encoder.Write(claimsJSON)
	signature := sig.Sign(secret, buf.String())
	buf.WriteByte('.')
	encoder.Write(signature)
	encoder.Close()
	return buf.String(), nil
}

func Decode(secret []byte, tokenStr string) (token Token, err error) {
	token.Header = make(map[string]interface{})
	token.Claims = make(map[string]interface{})
	claimsPos := strings.IndexByte(tokenStr, '.')
	if claimsPos == -1 {
		err = errors.ErrMalformedToken
		return
	}
	signaturePos := strings.LastIndexByte(tokenStr, '.')
	if signaturePos == claimsPos {
		err = errors.ErrMalformedToken
		return
	}
	encodedPayload := tokenStr[:signaturePos]
	encodedHeader := tokenStr[:claimsPos]
	encodedClaims := tokenStr[claimsPos+1 : signaturePos]
	encodedSignature := tokenStr[signaturePos+1:]
	// Verify signature
	signature, err := DefaultEncoding.DecodeString(encodedSignature)
	if err != nil {
		return
	}
	err = sig.Verify(secret, encodedPayload, signature)
	if err != nil {
		return
	}
	// Decode header
	err = decodeBase64JSON(encodedHeader, &token.Header)
	if err != nil {
		return
	}
	// Decode claims
	err = decodeBase64JSON(encodedClaims, &token.Claims)
	return
}

func VerifySignature(secret []byte, tokenStr string) error {
	signaturePos := strings.LastIndexByte(tokenStr, '.')
	if signaturePos == -1 {
		return errors.ErrMalformedToken
	}
	encodedPayload := tokenStr[:signaturePos]
	encodedSignature := tokenStr[signaturePos+1:]
	signature, err := DefaultEncoding.DecodeString(encodedSignature)
	if err != nil {
		return err
	}
	return sig.Verify(secret, encodedPayload, signature)
}

func decodeBase64JSON(data string, v interface{}) error {
	decoded, err := DefaultEncoding.DecodeString(data)
	err = json.Unmarshal(decoded, v)
	if err != nil {
		return err
	}
	return nil
}
