package main

import (
	"fmt"

	"time"

	"github.com/niktheblak/gojwt/token"
)

func main() {
	ctx := token.DefaultContext([]byte("secret"))
	token := ctx.NewToken()
	token.SetSubject("ntb")
	token.SetIssuedAt(time.Now())
	token.SetExpiration(time.Now().Add(time.Hour))
	token.SetClaim("admin", true)
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
