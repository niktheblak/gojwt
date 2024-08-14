package cmd

import (
	"github.com/spf13/cobra"
)

var (
	algorithm      string
	output         string
	publicKeyPath  string
	privateKeyPath string
)

var rootCmd = &cobra.Command{
	Use:          "gojwt",
	Short:        "gojwt is a library and utility to create and decode JWT tokens",
	SilenceUsage: true,
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&algorithm, "algorithm", "a", "HS256", "algorithm to use for creating tokens")
	rootCmd.PersistentFlags().StringVar(&publicKeyPath, "public-key", "", "path to file containing public key")
	rootCmd.PersistentFlags().StringVar(&privateKeyPath, "private-key", "", "path to file containing private key")
	rootCmd.PersistentFlags().StringVarP(&output, "output", "o", "", "write to file (stdout if empty)")
}

func Execute() error {
	return rootCmd.Execute()
}
