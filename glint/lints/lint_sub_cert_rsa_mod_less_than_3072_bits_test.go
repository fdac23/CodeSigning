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

func TestRsaModSizeTooSmall(t *testing.T) {
	inputPath := "../testlint/testCerts/subCertRsa1024Bits.pem"
	expected := Error
	out := Lints["e_rsa_mod_less_than_3072_bits"].Execute(ReadCertificate(inputPath))
	if out.Status != expected {
		t.Errorf("%s: expected %s, got %s", inputPath, expected, out.Status)
	}
}

func TestRsaModSize3072(t *testing.T) {
	inputPath := "../testlint/testCerts/subCertRsa3072Bits.pem"
	expected := Pass
	out := Lints["e_rsa_mod_less_than_3072_bits"].Execute(ReadCertificate(inputPath))
	if out.Status != expected {
		t.Errorf("%s: expected %s, got %s", inputPath, expected, out.Status)
	}
}

func TestRsaModSizeLarge(t *testing.T) {
	inputPath := "../testlint/testCerts/subCertRsa4096Bits.pem"
	expected := Pass
	out := Lints["e_rsa_mod_less_than_3072_bits"].Execute(ReadCertificate(inputPath))
	if out.Status != expected {
		t.Errorf("%s: expected %s, got %s", inputPath, expected, out.Status)
	}
}

func TestRsaModSizeTooSmallBeforeEffectiveDate(t *testing.T) {
	inputPath := "../testlint/testCerts/subCertRsa2048BitsIssued2020.pem"
	expected := NE
	out := Lints["e_rsa_mod_less_than_3072_bits"].Execute(ReadCertificate(inputPath))
	if out.Status != expected {
		t.Errorf("%s: expected %s, got %s", inputPath, expected, out.Status)
	}
}
