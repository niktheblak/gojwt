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

package tokencontext

import (
	"github.com/niktheblak/gojwt/pkg/sign"
)

type Context interface {
	Type() string
	Signer() sign.Signer
	CreateHeader() map[string]interface{}
}

type context struct {
	tokenType string
	signer    sign.Signer
}

func DefaultContext(secret []byte) Context {
	return &context{
		tokenType: "JWT",
		signer:    sign.HS256(secret),
	}
}

func ContextWithSigner(s sign.Signer) Context {
	return &context{
		tokenType: "JWT",
		signer:    s,
	}
}

func (c *context) Type() string {
	return c.tokenType
}

func (c *context) Signer() sign.Signer {
	return c.signer
}

func (c *context) CreateHeader() map[string]interface{} {
	header := make(map[string]interface{})
	header["typ"] = c.tokenType
	header["alg"] = c.signer.Algorithm()
	return header
}
