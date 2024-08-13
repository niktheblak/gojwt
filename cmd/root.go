package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	output      string
	secretPath  string
	secretBytes []byte
)

var rootCmd = &cobra.Command{
	Use:          "gojwt",
	Short:        "gojwt is a library and utility to create and decode JWT tokens",
	SilenceUsage: true,
	PreRunE: func(cmd *cobra.Command, args []string) error {
		if len(secretBytes) == 0 {
			if secretPath == "" {
				return fmt.Errorf("either secret or secret-bytes argument must be specified")
			}
			var err error
			secretBytes, err = os.ReadFile(secretPath)
			if err != nil {
				return err
			}
		}
		if len(secretBytes) == 0 {
			return fmt.Errorf("empty secret")
		}
		return nil
	},
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&secretPath, "secret", "s", "", "path to file containing JWT secret")
	rootCmd.PersistentFlags().BytesHexVar(&secretBytes, "secret-bytes", nil, "hex encoded secret")
	rootCmd.PersistentFlags().StringVarP(&output, "output", "o", "", "write to file (stdout if empty)")
}

func Execute() error {
	return rootCmd.Execute()
}
