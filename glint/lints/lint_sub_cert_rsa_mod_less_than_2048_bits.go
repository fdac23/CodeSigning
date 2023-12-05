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

type subCertRsaModSizeOld struct{}

/******************************************************************************
Added by: gbb823

Referenced from: MRfCSC v1.1, for certificates only issued prior to Jan 1, 2021

6.1.5.2 Code Signing Certificate and Timestamp Authority Key Sizes
	For Keys corresponding to Subscriber code signing and Timestamp Authority
	Certificates:
		• If the Key is RSA, then the modulus MUST be at least 2048 bits in length.
******************************************************************************/

func (l *subCertRsaModSizeOld) Initialize() error {
	return nil
}

func (l *subCertRsaModSizeOld) CheckApplies(c *x509.Certificate) bool {
	_, ok := c.PublicKey.(*rsa.PublicKey)
	return ok && c.PublicKeyAlgorithm == x509.RSA && c.NotBefore.Before(util.NoRSA2048Date) && util.IsSubscriberCert(c)
}

func (l *subCertRsaModSizeOld) Execute(c *x509.Certificate) *LintResult {
	key := c.PublicKey.(*rsa.PublicKey)
	if key.N.BitLen() < 2048 {
		return &LintResult{Status: Error}
	} else {
		return &LintResult{Status: Pass}
	}
}

func init() {
	RegisterLint(&Lint{
		Name:          "e_rsa_mod_less_than_2048_bits",
		Description:   "Subscriber Certificate: If the key is RSA, then the modulus MUST be at least 2048 bits in length. (Issed prior to Jan 1, 2021)",
		Citation:      "BRs: 6.1.5.2",
		Source:        MinimumRequirementsForCodeSigningCertificates,
		EffectiveDate: util.BRfCSCV21MinCryptoEffectiveDate, // 31 Jan 2017 as specified in BRfCSC v2.1
		Lint:          &subCertRsaModSizeOld{},
	})
}
