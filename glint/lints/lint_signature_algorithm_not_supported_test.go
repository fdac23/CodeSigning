package lints

/*
 * ZLint Copyright 2023 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

import (
	"testing"
)

func TestSignatureAlgorithmECDSASHA256Supported(t *testing.T) {
	inputPath := "../testlint/testCerts/ecdsaP256.pem"
	expected := Pass
	out := Lints["e_signature_algorithm_not_supported"].Execute(ReadCertificate(inputPath))
	if out.Status != expected {
		t.Errorf("%s: expected %s, got %s", inputPath, expected, out.Status)
	}
}

func TestSignatureAlgorithmDSASHA256Supported(t *testing.T) {
	inputPath := "../testlint/testCerts/dsaUniqueRep.pem"
	expected := Pass
	out := Lints["e_signature_algorithm_not_supported"].Execute(ReadCertificate(inputPath))
	if out.Status != expected {
		t.Errorf("%s: expected %s, got %s", inputPath, expected, out.Status)
	}
}

func TestSignatureAlgorithmDSASha1Warn(t *testing.T) {
	inputPath := "../testlint/testCerts/dsaShorterThan2048Bits.pem"
	expected := Warn
	out := Lints["e_signature_algorithm_not_supported"].Execute(ReadCertificate(inputPath))
	if out.Status != expected {
		t.Errorf("%s: expected %s, got %s", inputPath, expected, out.Status)
	}
}
