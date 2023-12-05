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
	"crypto/rsa"

	"github.com/moa-lab/code-signing-certs-lint/tree/main/glint/util"
	"github.com/zmap/zcrypto/x509"
)

type subCertRsaModSize struct{}

/******************************************************************************
Added by: gbb823

Referenced from: BRfCSC v3.4
First seen: MRfCSC v1.1, for certificates only issued on or after Jan 1, 2021

6.1.5.2 Code Signing Certificate and Timestamp Authority Key Sizes
	For Keys corresponding to Subscriber code signing and Timestamp Authority
	Certificates:
		• If the Key is RSA, then the modulus MUST be at least 3072 bits in length.
		• If the Key is ECDSA, then the curve MUST be one of NIST P‐256, P‐384, or P‐521.
		• If the Key is DSA, then one of the following key parameter options MUST be used:
			• Key length (L) of 2048 bits and modulus length (N) of 224 bits
			• Key length (L) of 2048 bits and modulus length (N) of 256 bits
******************************************************************************/

func (l *subCertRsaModSize) Initialize() error {
	return nil
}

func (l *subCertRsaModSize) CheckApplies(c *x509.Certificate) bool {
	_, ok := c.PublicKey.(*rsa.PublicKey)
	return ok && c.PublicKeyAlgorithm == x509.RSA && util.IsSubscriberCert(c)
}

func (l *subCertRsaModSize) Execute(c *x509.Certificate) *LintResult {
	key := c.PublicKey.(*rsa.PublicKey)
	if key.N.BitLen() < 3072 {
		return &LintResult{Status: Error}
	} else {
		return &LintResult{Status: Pass}
	}
}

func init() {
	RegisterLint(&Lint{
		Name:          "e_rsa_mod_less_than_3072_bits",
		Description:   "Subscriber Certificate: If the key is RSA, then the modulus MUST be at least 3072 bits in length.",
		Citation:      "BRs: 6.1.5.2",
		Source:        MinimumRequirementsForCodeSigningCertificates,
		EffectiveDate: util.NoRSA2048Date, // June 1st, 2021
		Lint:          &subCertRsaModSize{},
	})
}
