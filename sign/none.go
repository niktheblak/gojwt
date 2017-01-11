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

package sign

type noneSigner struct {
}

func None() Signer {
	return noneSigner{}
}

func (s noneSigner) Algorithm() string {
	return "none"
}

func (s noneSigner) Sign(data string) []byte {
	return nil
}

func (s noneSigner) Verify(data string, signature []byte) error {
	return nil
}
