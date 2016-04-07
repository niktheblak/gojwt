package sign

type noneSigner struct {
}

func None() Signer {
	return noneSigner{}
}

func (s noneSigner) Algorithm() string {
	return "none"
}

func (s noneSigner) Sign(data string) []byte {
	return nil
}

func (s noneSigner) Verify(data string, signature []byte) error {
	return nil
}
