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
	"crypto/ecdsa"

	"github.com/moa-lab/code-signing-certs-lint/tree/main/glint/util"
	"github.com/zmap/zcrypto/x509"
)

type ecdsaImproperCurves struct{}

/******************************************************************************
Added by: gbb823

Referenced from: BRfCSC v3.4
First seen: MRfCSC v1.1

6.1.5.2 Code Signing Certificate and Timestamp Authority Key Sizes
	For Keys corresponding to Subscriber code signing and Timestamp Authority
	Certificates:
		• If the Key is ECDSA, then the curve MUST be one of NIST P-256, P-384, or P-521.
******************************************************************************/

func (l *ecdsaImproperCurves) Initialize() error {
	return nil
}

func (l *ecdsaImproperCurves) CheckApplies(c *x509.Certificate) bool {
	return c.PublicKeyAlgorithm == x509.ECDSA && util.IsSubscriberCert(c)
}

func (l *ecdsaImproperCurves) Execute(c *x509.Certificate) *LintResult {
	/* Declare theKey to be a ECDSA Public Key */
	var theKey *ecdsa.PublicKey
	/* Need to do different things based on what c.PublicKey is */
	switch keyType := c.PublicKey.(type) {
	case *x509.AugmentedECDSA:
		theKey = keyType.Pub
	case *ecdsa.PublicKey:
		theKey = keyType
	}
	/* Now can actually check the params */
	theParams := theKey.Curve.Params()
	switch theParams.Name {
	case "P-256", "P-384", "P-521":
		return &LintResult{Status: Pass}
	default:
		return &LintResult{Status: Error}
	}
}

func init() {
	RegisterLint(&Lint{
		Name:          "e_ec_improper_curves",
		Description:   "If the Key is ECDSA, then the curve MUST be one of NIST P-256, P-384, or P-521.",
		Citation:      "BRs: 6.1.5.2",
		Source:        MinimumRequirementsForCodeSigningCertificates,
		EffectiveDate: util.BRfCSCV21MinCryptoEffectiveDate, // Jan 31, 2017
		Lint:          &ecdsaImproperCurves{},
	})
}
