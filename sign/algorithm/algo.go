package algorithm

import (
	"crypto/sha256"
	"hash"
)

type Algorithm struct {
	Name string
	Hash func() hash.Hash
}

func (algo Algorithm) String() string {
	return algo.Name
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

func None() Algorithm {
	return Algorithms["none"]
}

func HS256() Algorithm {
	return Algorithms["HS256"]
}
