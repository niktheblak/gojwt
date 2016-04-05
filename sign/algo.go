package sign

import (
	"crypto/sha256"
	"hash"
)

type Algorithm struct {
	Name string
	Hash func() hash.Hash
}

var Algorithms = map[string]Algorithm{
	"none": Algorithm{
		Name: "none",
		Hash: nil,
	},
	"HS256": Algorithm{
		Name: "HS256",
		Hash: sha256.New,
	},
}

func (algo Algorithm) String() string {
	return algo.Name
}
