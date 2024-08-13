package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/niktheblak/gojwt/pkg/jwt"
	"github.com/niktheblak/gojwt/pkg/tokencontext"
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
		tokenContext := tokencontext.DefaultContext(secretBytes)
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
		token, err := jwt.Decode(tokenContext, tokenStr)
		if err != nil {
			if force {
				fmt.Fprintf(cmd.ErrOrStderr(), "Warning: token is not valid: %v\n", err)
				cmd.Println(token.String())
				return nil
			}
			return err
		}
		cmd.Println(token.String())
		return nil
	},
}

func init() {
	decodeCmd.Flags().StringVarP(&input, "input", "i", "", "read JWT token from file (stdin if empty)")
	decodeCmd.Flags().BoolVarP(&force, "force", "f", false, "print token data even if token is not valid")

	rootCmd.AddCommand(decodeCmd)
}
