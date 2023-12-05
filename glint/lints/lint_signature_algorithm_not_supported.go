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
	"github.com/moa-lab/code-signing-certs-lint/tree/main/glint/util"
	"github.com/zmap/zcrypto/x509"
)

type signatureAlgorithmNotSupported struct{}

/*
*****************************************************************************
Added by: jsteed

Referenced from: BRfCSC v3.4
First seen: BRfCSC v3.0

7.1.3.2.1 RSA

	The CA SHALL use one of the following signature algorithms:
		• RSASSA‐PKCS1‐v1_5 with SHA‐256
		• RSASSA‐PKCS1‐v1_5 with SHA‐384
		• RSASSA‐PKCS1‐v1_5 with SHA‐512
		• RSASSA‐PSS with SHA‐256
		• RSASSA‐PSS with SHA‐384
		• RSASSA‐PSS with SHA‐512

7.1.3.2.2 ECDSA

	The CA SHALL use one of the following signature algorithms:
		• ECDSA with SHA‐256
		• ECDSA with SHA‐384
		• ECDSA with SHA‐512

7.1.3.2.3 DSA

	The CA SHALL use the following signature algorithm:
		• DSA with SHA‐256
	In addition, the CA MAY use DSA with SHA-1 if one of the following conditions are met:
		• It is used within Timestamp Authority Certificate and the date of the notBefore field is not
	greater than 2022‐04‐30; or,
		• It is used within an OCSP response; or,
		• It is used within a CRL; or,
		• It is used within a Timestamp Token and the date of the genTime field is not greater than
			2022‐04‐30.

*****************************************************************************
*/
var (
	// Any of the following x509.SignatureAlgorithms are acceptable per §7.1.3.2 of
	// the BRs.
	passSigAlgs = map[x509.SignatureAlgorithm]bool{
		x509.SHA256WithRSA:   true,
		x509.SHA384WithRSA:   true,
		x509.SHA512WithRSA:   true,
		x509.DSAWithSHA256:   true,
		x509.ECDSAWithSHA256: true,
		x509.ECDSAWithSHA384: true,
		x509.ECDSAWithSHA512: true,
	}
	// The BRs do not forbid the use of RSA-PSS as a signature scheme in
	// certificates but it is not broadly supported by user-agents. Since
	// the BRs do not forbid the practice we return a warning result.
	// NOTE: The Mozilla root program policy *does* forbid their use since v2.7.
	// This should be covered by a lint scoped to the Mozilla source instead of in
	// this CABF lint.
	warnSigAlgs = map[x509.SignatureAlgorithm]bool{
		x509.SHA256WithRSAPSS: true,
		x509.SHA384WithRSAPSS: true,
		x509.SHA512WithRSAPSS: true,
		x509.DSAWithSHA1:      true,
		x509.SHA1WithRSA:      true,
	}
)

func (l *signatureAlgorithmNotSupported) Initialize() error {
	return nil
}

func (l *signatureAlgorithmNotSupported) CheckApplies(c *x509.Certificate) bool {
	return util.IsSubscriberCert(c)
}

func (l *signatureAlgorithmNotSupported) Execute(c *x509.Certificate) *LintResult {
	sigAlg := c.SignatureAlgorithm
	status := Error
	if passSigAlgs[sigAlg] {
		status = Pass
	} else if warnSigAlgs[sigAlg] {
		status = Warn
	}
	return &LintResult{
		Status: status,
	}
}

func init() {
	RegisterLint(&Lint{
		Name:          "e_signature_algorithm_not_supported",
		Description:   "Certificates MUST meet the following requirements for algorithm Source: SHA-256, SHA-384, SHA-512",
		Citation:      "BRs: 7.1.3.2.1, 7.1.3.2.2, and 7.1.3.2.3",
		Source:        MinimumRequirementsForCodeSigningCertificates,
		EffectiveDate: util.MRfCSCEffectiveDate,
		Lint:          &signatureAlgorithmNotSupported{},
	})
}
