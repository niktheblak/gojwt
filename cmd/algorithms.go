package cmd

import (
	"github.com/golang-jwt/jwt/v5"
	"github.com/spf13/cobra"
)

var algorithmsCommand = &cobra.Command{
	Use:          "algorithms",
	Short:        "List supported JWT signing algorithms",
	SilenceUsage: true,
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Println(jwt.SigningMethodHS256.Name)
		cmd.Println(jwt.SigningMethodHS512.Name)
		cmd.Println(jwt.SigningMethodRS256.Name)
		cmd.Println(jwt.SigningMethodRS384.Name)
		cmd.Println(jwt.SigningMethodRS512.Name)
		cmd.Println(jwt.SigningMethodES256.Name)
		cmd.Println(jwt.SigningMethodES384.Name)
		cmd.Println(jwt.SigningMethodES512.Name)
		cmd.Println(jwt.SigningMethodEdDSA.Alg())
		cmd.Println(jwt.SigningMethodPS256.Name)
		cmd.Println(jwt.SigningMethodPS384.Name)
		cmd.Println(jwt.SigningMethodPS512.Name)
	},
}

func init() {
	rootCmd.AddCommand(algorithmsCommand)
}
