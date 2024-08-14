package cmd

import (
	"encoding/json"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/niktheblak/gojwt/pkg/jwt"
	"github.com/niktheblak/gojwt/pkg/sign"
)

var (
	header      string
	payload     string
	headerFile  string
	payloadFile string
	validity    time.Duration
)

var encodeCmd = &cobra.Command{
	Use:          "encode",
	Short:        "Encodes the given values into a JWT token",
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		headerMap := make(map[string]any)
		if len(headerFile) > 0 {
			data, err := os.ReadFile(headerFile)
			if err != nil {
				return err
			}
			if err := json.Unmarshal(data, &headerMap); err != nil {
				return err
			}
		} else {
			if err := json.Unmarshal([]byte(header), &headerMap); err != nil {
				return err
			}
		}
		payloadMap := make(map[string]any)
		if len(payloadFile) > 0 {
			data, err := os.ReadFile(payloadFile)
			if err != nil {
				return err
			}
			if err := json.Unmarshal(data, &payloadMap); err != nil {
				return err
			}
		} else {
			if err := json.Unmarshal([]byte(payload), &payloadMap); err != nil {
				return err
			}
		}
		alg, err := sign.ParseAlgorithm(algorithm)
		if err != nil {
			return err
		}
		token := jwt.NewToken(contexts[alg])
		token.Header = headerMap
		token.Payload = payloadMap
		ts := time.Now()
		token.SetIssuedAt(ts)
		token.SetExpiration(ts.Add(validity))
		tokenStr, err := token.Encode()
		if err != nil {
			return err
		}
		if len(output) > 0 {
			if err := os.WriteFile(output, []byte(tokenStr), 0644); err != nil {
				return err
			}
		} else {
			cmd.Println(tokenStr)
		}
		return nil
	},
}

func init() {
	encodeCmd.Flags().StringVarP(&header, "header", "H", "", "JWT header JSON")
	encodeCmd.Flags().StringVarP(&payload, "payload", "p", "", "JWT payload JSON")
	encodeCmd.Flags().StringVar(&headerFile, "header-file", "", "path to JWT header JSON")
	encodeCmd.Flags().StringVar(&payloadFile, "payload-file", "", "path to JWT payload JSON")
	encodeCmd.Flags().DurationVar(&validity, "validity", 1*time.Hour, "JWT validity period")

	rootCmd.AddCommand(encodeCmd)
}
