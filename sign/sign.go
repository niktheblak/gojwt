package sign

import "errors"

type Algorithm int

// List of signing algorithms
const (
	AlgoUnknown Algorithm = iota
	AlgoNone
	AlgoHS256
	AlgoHS384
	AlgoHS512
	AlgoRS256
	AlgoRS384
	AlgoRS512
)

func (algo Algorithm) String() string {
	name, ok := AlgorithmNames[algo]
	if ok {
		return name
	}
	return string(algo)
}

var AlgorithmNames = map[Algorithm]string{
	AlgoNone:  "none",
	AlgoHS256: "HS256",
	AlgoHS384: "HS384",
	AlgoHS512: "HS512",
	AlgoRS256: "RS256",
	AlgoRS384: "RS384",
	AlgoRS512: "RS512",
}

var AlgorithmsByName map[string]Algorithm

// Signature-related errors
var (
	ErrInvalidSignature = errors.New("Invalid signature")
)

func init() {
	AlgorithmsByName = make(map[string]Algorithm)
	for k, v := range AlgorithmNames {
		AlgorithmsByName[v] = k
	}
}

type Signer interface {
	Algorithm() Algorithm
	Sign(data string) []byte
	Verify(data string, signature []byte) error
}
