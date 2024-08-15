package cmd

import (
	"maps"
	"slices"

	"github.com/spf13/cobra"

	"github.com/niktheblak/gojwt/pkg/signing"
)

var algorithmsCommand = &cobra.Command{
	Use:          "algorithms",
	Short:        "List supported JWT signing algorithms",
	SilenceUsage: true,
	Run: func(cmd *cobra.Command, args []string) {
		for _, algorithm := range slices.Sorted(maps.Keys(signing.Methods)) {
			cmd.Println(algorithm)
		}
	},
}

func init() {
	rootCmd.AddCommand(algorithmsCommand)
}
