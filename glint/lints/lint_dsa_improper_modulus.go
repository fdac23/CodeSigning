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
	"github.com/zmap/zcrypto/dsa"

	"github.com/moa-lab/code-signing-certs-lint/tree/main/glint/util"
	"github.com/zmap/zcrypto/x509"
)

type dsaImproperModSize struct{}

/******************************************************************************
Added by: gbb823

Referenced from: BRfCSC v3.4
First seen: MRfCSC v1.1

6.1.5.2 Code Signing Certificate and Timestamp Authority Key Sizes
	For Keys corresponding to Subscriber code signing and Timestamp Authority
	Certificates:
		• If the Key is DSA, then one of the following key parameter options MUST be used:
			• Key length (L) of 2048 bits and modulus length (N) of 224 bits
			• Key length (L) of 2048 bits and modulus length (N) of 256 bits
******************************************************************************/

func (l *dsaImproperModSize) Initialize() error {
	return nil
}

func (l *dsaImproperModSize) CheckApplies(c *x509.Certificate) bool {
	return c.PublicKeyAlgorithm == x509.DSA && util.IsSubscriberCert(c)
}

func (l *dsaImproperModSize) Execute(c *x509.Certificate) *LintResult {
	dsaKey, ok := c.PublicKey.(*dsa.PublicKey)
	if !ok {
		return &LintResult{Status: NA}
	}
	dsaParams := dsaKey.Parameters
	N := dsaParams.Q.BitLen()
	if N == 224 || N == 256 {
		return &LintResult{Status: Pass}
	}
	return &LintResult{Status: Error}
}

func init() {
	RegisterLint(&Lint{
		Name:          "e_dsa_improper_modulus",
		Description:   "If the Key is DSA, than modulus length (N) must be either 224 or 256 bits.",
		Citation:      "BRs: 6.1.5.2",
		Source:        MinimumRequirementsForCodeSigningCertificates,
		EffectiveDate: util.BRfCSCV21MinCryptoEffectiveDate, // Jan 31, 2017
		Lint:          &dsaImproperModSize{},
	})
}
