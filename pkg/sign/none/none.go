package none

import (
	"github.com/niktheblak/gojwt/pkg/sign"
)

type noneSigner struct {
}

func None() sign.Signer {
	return noneSigner{}
}

func (s noneSigner) Algorithm() string {
	return "none"
}

func (s noneSigner) Sign(data string) ([]byte, error) {
	return nil, nil
}

func (s noneSigner) Verify(data string, signature []byte) error {
	return nil
}
