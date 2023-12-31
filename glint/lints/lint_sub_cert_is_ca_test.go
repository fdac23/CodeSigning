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

func TestSubCertIsNotCA(t *testing.T) {
	inputPath := "../testlint/testCerts/subCertIsNotCA.pem"
	expected := Pass
	out := Lints["e_sub_cert_is_ca"].Execute(ReadCertificate(inputPath))
	if out.Status != expected {
		t.Errorf("%s: expected %s, got %s", inputPath, expected, out.Status)
	}
}

func TestSubCertIsCA(t *testing.T) {
	inputPath := "../testlint/testCerts/subCertIsCA.pem"
	expected := Error
	out := Lints["e_sub_cert_is_ca"].Execute(ReadCertificate(inputPath))
	if out.Status != expected {
		t.Errorf("%s: expected %s, got %s", inputPath, expected, out.Status)
	}
}

func TestSubCertNoBasicConstraints(t *testing.T) {
	inputPath := "../testlint/testCerts/subCertNoBasicConstraints.pem"
	expected := Pass
	out := Lints["e_sub_cert_is_ca"].Execute(ReadCertificate(inputPath))
	if out.Status != expected {
		t.Errorf("%s: expected %s, got %s", inputPath, expected, out.Status)
	}
}
