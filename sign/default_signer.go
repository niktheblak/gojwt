package sign

import (
	"crypto/hmac"
	"hash"
)

type defaultSigner struct {
	algo   Algorithm
	secret []byte
}

func New(algo Algorithm, secret []byte) Signer {
	return defaultSigner{
		algo:   algo,
		secret: secret,
	}
}

func (s defaultSigner) newMac() hash.Hash {
	return hmac.New(s.algo.Hash, s.secret)
}

func (s defaultSigner) Algorithm() Algorithm {
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
