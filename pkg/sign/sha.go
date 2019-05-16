/*
  Copyright 2017 Niko Korhonen

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
 */

package sign

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
)

type shaSigner struct {
	algo   string
	hash   func() hash.Hash
	secret []byte
}

func HS256(secret []byte) Signer {
	return shaSigner{
		algo:   "HS256",
		hash:   sha256.New,
		secret: secret,
	}
}

func ES256(secret []byte) Signer {
	return shaSigner{
		algo:   "ES256",
		hash:   sha512.New512_256,
		secret: secret,
	}
}

func (s shaSigner) newMac() hash.Hash {
	return hmac.New(s.hash, s.secret)
}

func (s shaSigner) Algorithm() string {
	return s.algo
}

func (s shaSigner) Sign(data string) []byte {
	mac := s.newMac()
	mac.Write([]byte(data))
	return mac.Sum(nil)
}

func (s shaSigner) Verify(data string, signature []byte) error {
	mac := s.newMac()
	mac.Write([]byte(data))
	expectedSignature := mac.Sum(nil)
	if !hmac.Equal(signature, expectedSignature) {
		return ErrInvalidSignature
	}
	return nil
}
