package encoder

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"

	"github.com/niktheblak/jwt/errors"
	sig "github.com/niktheblak/jwt/signature"
)

var DefaultEncoding = base64.RawURLEncoding

func Encode(secret []byte, header map[string]string, claims map[string]interface{}) (string, error) {
	var buf bytes.Buffer
	encoder := base64.NewEncoder(DefaultEncoding, &buf)
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	encoder.Write(headerJSON)
	buf.WriteByte('.')
	claimsJSON, err := json.Marshal(claims)
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

func Decode(secret []byte, tokenStr string) (header map[string]string, claims map[string]interface{}, err error) {
	header = make(map[string]string)
	claims = make(map[string]interface{})
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
	payloadStr := tokenStr[:signaturePos]
	headerStr := tokenStr[:claimsPos]
	claimsStr := tokenStr[claimsPos+1 : signaturePos]
	signatureStr := tokenStr[signaturePos+1:]
	// Verify signature
	rawSignature, err := DefaultEncoding.DecodeString(signatureStr)
	if err != nil {
		return
	}
	err = sig.Verify(secret, payloadStr, rawSignature)
	if err != nil {
		return
	}
	// Decode header
	err = decodeBase64JSON(headerStr, &header)
	if err != nil {
		return
	}
	// Decode claims
	err = decodeBase64JSON(claimsStr, &claims)
	if err != nil {
		return
	}
	err = validateHeader(header)
	return
}

func VerifySignature(secret []byte, tokenStr string) error {
	signaturePos := strings.LastIndexByte(tokenStr, '.')
	if signaturePos == -1 {
		return errors.ErrMalformedToken
	}
	payloadBytes := tokenStr[:signaturePos]
	signatureBytes := tokenStr[signaturePos+1:]
	signature, err := DefaultEncoding.DecodeString(signatureBytes)
	if err != nil {
		return err
	}
	return sig.Verify(secret, payloadBytes, signature)
}

func validateHeader(header map[string]string) error {
	alg, ok := header["alg"]
	if !ok {
		return errors.ErrInvalidHeader
	}
	if alg != "HS256" {
		return errors.ErrInvalidAlgorithm
	}
	typ, ok := header["typ"]
	if !ok {
		return errors.ErrInvalidHeader
	}
	if typ != "JWT" {
		return errors.ErrInvalidType
	}
	return nil
}

func decodeBase64JSON(data string, v interface{}) error {
	decoded, err := DefaultEncoding.DecodeString(data)
	err = json.Unmarshal(decoded, v)
	if err != nil {
		return err
	}
	return nil
}
