/*
  Copyright 2017 Niko Korhonen

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
 */

package base64json

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
)

var Encoding = base64.RawURLEncoding

func Decode(data string, v interface{}) error {
	if data == "" {
		return nil
	}
	buf := bytes.NewBufferString(data)
	base64Dec := base64.NewDecoder(Encoding, buf)
	jsonDec := json.NewDecoder(base64Dec)
	return jsonDec.Decode(v)
}

func Encode(v interface{}, w io.Writer) error {
	base64Enc := base64.NewEncoder(Encoding, w)
	jsonEnc := json.NewEncoder(base64Enc)
	err := jsonEnc.Encode(v)
	if err != nil {
		return err
	}
	return base64Enc.Close()
}

func EncodeBase64(data []byte, w io.Writer) error {
	base64Enc := base64.NewEncoder(Encoding, w)
	_, err := base64Enc.Write(data)
	if err != nil {
		return err
	}
	return base64Enc.Close()
}
