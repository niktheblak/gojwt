package cmd

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/spf13/cobra"

	"github.com/niktheblak/gojwt/pkg/signing"
)

var (
	input string
	force bool
)

var decodeCmd = &cobra.Command{
	Use:          "decode",
	Short:        "Decodes and prints the contents of the given JWT token",
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		if publicKeyPath == "" {
			return fmt.Errorf("argument --public-key must be specified")
		}
		var tokenStr string
		if input != "" {
			content, err := os.ReadFile(input)
			if err != nil {
				return err
			}
			tokenStr = string(content)
		} else {
			scanner := bufio.NewScanner(os.Stdin)
			scanner.Scan()
			if scanner.Err() != nil {
				return scanner.Err()
			}
			tokenStr = strings.TrimSpace(scanner.Text())
		}
		var invalidToken jwt.Token
		token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
			invalidToken = *token
			if err := signing.ValidateMethod(algorithm, token); err != nil {
				return nil, err
			}
			return signing.LoadVerifyKey(algorithm, publicKeyPath)
		})
		if err != nil {
			if force {
				fmt.Fprintf(cmd.ErrOrStderr(), "Warning: token is not valid: %v\n", err)
				printToken(cmd.OutOrStdout(), &invalidToken)
				return nil
			}
			return err
		}
		printToken(cmd.OutOrStdout(), token)
		return nil
	},
}

func init() {
	decodeCmd.Flags().StringVarP(&input, "input", "i", "", "read JWT token from file (stdin if empty)")
	decodeCmd.Flags().BoolVarP(&force, "force", "f", false, "print token data even if token is not valid")

	rootCmd.AddCommand(decodeCmd)
}

func printToken(w io.Writer, token *jwt.Token) {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(token.Header); err != nil {
		panic(err)
	}
	if err := enc.Encode(token.Claims); err != nil {
		panic(err)
	}
}
