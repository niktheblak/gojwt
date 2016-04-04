package hs256

import (
	"crypto/hmac"
	"crypto/sha256"
	"hash"

	"github.com/niktheblak/jwt/sign"
)

type signerHS256 struct {
	secret []byte
}

func New(secret []byte) sign.Signer {
	return &signerHS256{secret}
}

func (s signerHS256) Algorithm() sign.Algorithm {
	return sign.AlgoHS256
}

func (s signerHS256) Sign(data string) []byte {
	mac := s.NewMac()
	mac.Write([]byte(data))
	return mac.Sum(nil)
}

func (s signerHS256) Verify(data string, signature []byte) error {
	mac := s.NewMac()
	mac.Write([]byte(data))
	return sign.VerifyMAC(mac, signature)
}

func (s signerHS256) NewMac() hash.Hash {
	return hmac.New(sha256.New, s.secret)
}
