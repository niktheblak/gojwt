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
	force bool
)

var decodeCmd = &cobra.Command{
	Use:          "decode",
	Short:        "Decodes and prints the contents of the given JWT token",
	SilenceUsage: true,
	Args:         cobra.MinimumNArgs(0),
	RunE: func(cmd *cobra.Command, args []string) error {
		if publicKeyPath == "" {
			return fmt.Errorf("argument --public-key must be specified")
		}
		if err := signing.ValidateAlgorithm(algorithm); err != nil {
			return err
		}
		if len(args) > 0 {
			for _, path := range args {
				content, err := os.ReadFile(path)
				if err != nil {
					return err
				}
				tokenStr := string(content)
				if err := parseToken(cmd, tokenStr); err != nil {
					return err
				}
			}
			return nil
		}
		scanner := bufio.NewScanner(os.Stdin)
		scanner.Scan()
		if scanner.Err() != nil {
			return scanner.Err()
		}
		tokenStr := strings.TrimSpace(scanner.Text())
		return parseToken(cmd, tokenStr)
	},
}

func init() {
	decodeCmd.Flags().BoolVarP(&force, "force", "f", false, "print token data even if token is not valid")

	rootCmd.AddCommand(decodeCmd)
}

func parseToken(cmd *cobra.Command, tokenStr string) error {
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
			return printToken(cmd.OutOrStdout(), &invalidToken)
		}
		return err
	}
	return printToken(cmd.OutOrStdout(), token)
}

func printToken(w io.Writer, token *jwt.Token) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(token.Header); err != nil {
		return err
	}
	if err := enc.Encode(token.Claims); err != nil {
		return err
	}
	return nil
}
