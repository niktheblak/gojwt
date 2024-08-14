package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/niktheblak/gojwt/pkg/sign"
	"github.com/niktheblak/gojwt/pkg/sign/rsa"
	"github.com/niktheblak/gojwt/pkg/sign/sha"
	"github.com/niktheblak/gojwt/pkg/tokencontext"
)

var (
	algorithm     string
	output        string
	shaSecretPath string
	rsaKeyPath    string
)

var contexts map[sign.Algorithm]tokencontext.Context

var rootCmd = &cobra.Command{
	Use:          "gojwt",
	Short:        "gojwt is a library and utility to create and decode JWT tokens",
	SilenceUsage: true,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		contexts = make(map[sign.Algorithm]tokencontext.Context)
		if shaSecretPath != "" {
			secret, err := os.ReadFile(shaSecretPath)
			if err != nil {
				return err
			}
			contexts[sign.HS256] = tokencontext.ContextWithSigner(sha.HS256(secret))
		}
		if rsaKeyPath != "" {
			key, err := rsa.LoadPrivateKey(rsaKeyPath)
			if err != nil {
				return err
			}
			contexts[sign.RS256] = tokencontext.ContextWithSigner(rsa.RS256(key))
		}
		if len(contexts) == 0 {
			return fmt.Errorf("no signers provided")
		}
		alg, err := sign.ParseAlgorithm(algorithm)
		if err != nil {
			return err
		}
		algOK := false
		for a := range contexts {
			if alg == a {
				algOK = true
			}
		}
		if !algOK {
			return fmt.Errorf("given algorithm is not supported by any any signer")
		}
		return nil
	},
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&algorithm, "algorithm", "a", "HS256", "algorithm to use for creating tokens (HS256 or RS256")
	rootCmd.PersistentFlags().StringVarP(&shaSecretPath, "sha-secret", "s", "", "path to file containing SHA secret")
	rootCmd.PersistentFlags().StringVar(&rsaKeyPath, "rsa-key", "", "path to file containing PEM encoded RSA key")
	rootCmd.PersistentFlags().StringVarP(&output, "output", "o", "", "write to file (stdout if empty)")
}

func Execute() error {
	return rootCmd.Execute()
}
