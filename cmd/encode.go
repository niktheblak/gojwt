package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/golang-jwt/jwt/v5"

	"github.com/niktheblak/gojwt/pkg/signing"
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
		if err := signing.ValidateAlgorithm(algorithm); err != nil {
			return err
		}
		headerMap := make(map[string]any)
		if len(headerFile) > 0 {
			data, err := os.ReadFile(headerFile)
			if err != nil {
				return err
			}
			if err := json.Unmarshal(data, &headerMap); err != nil {
				return err
			}
		} else if len(header) > 0 {
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
		} else if len(payload) > 0 {
			if err := json.Unmarshal([]byte(payload), &payloadMap); err != nil {
				return err
			}
		}
		signingMethod := signing.GetMethod(algorithm)
		token := jwt.New(signingMethod)
		headerMap["alg"] = signingMethod.Alg()
		token.Header = headerMap
		ensureValidity(payloadMap)
		token.Claims = jwt.MapClaims(payloadMap)
		if privateKeyPath == "" {
			return fmt.Errorf("argument --private-key must be specified")
		}
		key, err := signing.LoadSigningKey(algorithm, privateKeyPath)
		if err != nil {
			return err
		}
		tokenStr, err := token.SignedString(key)
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

func ensureValidity(payload map[string]any) {
	now := time.Now().UTC()
	iatValid := true
	iat, ok := extractTS(payload, "iat")
	if !ok {
		iatValid = false
	}
	if iat.After(now) {
		iatValid = false
	}
	if !iatValid {
		iat = now
		payload["iat"] = iat.Unix()
	}
	expValid := true
	exp, ok := extractTS(payload, "exp")
	if !ok {
		expValid = false
	}
	if exp.Before(now) {
		expValid = false
	}
	if !expValid {
		exp = now.Add(validity)
		payload["exp"] = exp.Unix()
	}
	nbf, ok := extractTS(payload, "nbf")
	if ok {
		if nbf.Before(iat) || nbf.After(exp) {
			delete(payload, "nbf")
		}
	}
}

func extractTS(payload map[string]any, field string) (time.Time, bool) {
	rawTS, ok := payload[field]
	if !ok {
		return time.Time{}, false
	}
	var intTS int64
	switch t := rawTS.(type) {
	case int64:
		intTS = t
	case float64:
		intTS = int64(t)
	default:
		return time.Time{}, false
	}
	return time.Unix(intTS, 0), true
}
