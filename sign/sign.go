package sign

type Signer interface {
	Algorithm() string
	Sign(data string) []byte
	Verify(data string, signature []byte) error
}
