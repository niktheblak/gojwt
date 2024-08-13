package main

import (
	"os"

	"github.com/niktheblak/gojwt/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
