package sign

import (
	"crypto/hmac"
	"hash"

	"github.com/niktheblak/jwt/sign/algorithm"
)

type defaultSigner struct {
	algo   algorithm.Algorithm
	secret []byte
}

func New(algo algorithm.Algorithm, secret []byte) Signer {
	return defaultSigner{
		algo:   algo,
		secret: secret,
	}
}

func (s defaultSigner) newMac() hash.Hash {
	return hmac.New(s.algo.Hash, s.secret)
}

func (s defaultSigner) Algorithm() algorithm.Algorithm {
	return s.algo
}

func (s defaultSigner) Sign(data string) []byte {
	mac := s.newMac()
	mac.Write([]byte(data))
	return mac.Sum(nil)
}

func (s defaultSigner) Verify(data string, signature []byte) error {
	mac := s.newMac()
	mac.Write([]byte(data))
	return VerifyMAC(mac, signature)
}
