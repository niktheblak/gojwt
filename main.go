package main

import (
	"fmt"

	"github.com/niktheblak/gojwt/token"
)

func main() {
	ctx := token.DefaultContext([]byte("secret"))
	token := ctx.NewToken()
	token.AddClaim("sub", "ntb")
	token.AddClaim("admin", true)
	fmt.Printf("Token:\n%v\n", token)
	encoded, err := token.Encode()
	if err != nil {
		panic(err)
	}
	fmt.Printf("Encoded: %s\n", encoded)
	decoded, err := ctx.Decode(encoded)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	}
	fmt.Printf("Decoded:\n%v\n", decoded)
}
