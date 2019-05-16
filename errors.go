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

package jwt

import (
	"errors"
)

// Errors related to JSON web tokens
var (
	ErrInvalidToken       = errors.New("token is not valid")
	ErrInvalidHeader      = errors.New("token has invalid header")
	ErrInvalidType        = errors.New("invalid token type")
	ErrInvalidAlgorithm   = errors.New("invalid or unsupported signing algorithm")
	ErrInvalidTimestamp   = errors.New("invalid timestamp")
	ErrMalformedToken     = errors.New("malformed token content")
	ErrContextNotSet      = errors.New("token context has not been set")
)
