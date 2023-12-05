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

type dsaTooShort struct{}

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

func (l *dsaTooShort) Initialize() error {
	return nil
}

func (l *dsaTooShort) CheckApplies(c *x509.Certificate) bool {
	return c.PublicKeyAlgorithm == x509.DSA && util.IsSubscriberCert(c)
}

func (l *dsaTooShort) Execute(c *x509.Certificate) *LintResult {
	dsaKey, ok := c.PublicKey.(*dsa.PublicKey)
	if !ok {
		return &LintResult{Status: NA}
	}
	dsaParams := dsaKey.Parameters
	L := dsaParams.P.BitLen()
	if L >= 2048 {
		return &LintResult{Status: Pass}
	}
	return &LintResult{Status: Error}
}

func init() {
	RegisterLint(&Lint{
		Name:          "e_dsa_shorter_than_2048_bits",
		Description:   "If the Key is DSA, than the key length (L) must be at least 2048 bits.",
		Citation:      "BRs: 6.1.5.2",
		Source:        MinimumRequirementsForCodeSigningCertificates,
		EffectiveDate: util.BRfCSCV21MinCryptoEffectiveDate, // Jan 31, 2017
		Lint:          &dsaTooShort{},
	})
}
