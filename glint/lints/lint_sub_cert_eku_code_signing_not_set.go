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

type subCertExtKeyUsageCodeSigningNotSet struct{}

/******************************************************************************
Added by: gbb823

Referenced from: BRfCSC v3.4
First seen: MRfCSC v1.1

7.1.2.3.f extKeyUsage
	If the Certificate is a Code Signing Certificate, then id-kp-codeSigning MUST
	be present and the following EKUs MAY be present:
		•	Lifetime Signing OID (1.3.6.1.4.1.311.10.3.13)
		• 	id-kp-emailProtection
		• 	Document Signing (1.3.6.1.4.1.311.3.10.3.12)
	If the Certificate is a Timestamp Certificate, then id-kp-timeStamping MUST
	be present and MUST be marked critical.
	Additionally, the following EKUs MUST NOT be present:
		•	 anyExtendedKeyUsage
		• 	id-kp-serverAuth
	Other values SHOULD NOT be present. If any other value is present, the CA MUST
	have a business agreement with a Platform vendor requiring that EKU in order to
	issue a Platform‐specific code signing certificate with that EKU.
******************************************************************************/

func (l *subCertExtKeyUsageCodeSigningNotSet) Initialize() error {
	return nil
}

func (l *subCertExtKeyUsageCodeSigningNotSet) CheckApplies(c *x509.Certificate) bool {
	return util.IsSubscriberCert(c) && c.ExtKeyUsage != nil
}

func (l *subCertExtKeyUsageCodeSigningNotSet) Execute(c *x509.Certificate) *LintResult {
	for _, kp := range c.ExtKeyUsage {
		if kp == x509.ExtKeyUsageCodeSigning {
			return &LintResult{Status: Pass}
		}
	}

	return &LintResult{Status: Error}
}

func init() {
	RegisterLint(&Lint{
		Name:          "e_sub_cert_eku_code_signing_not_set",
		Description:   "Subscriber Certificate: extKeyUsage If the Certificate is a Code Signing Certificate, then id-kp-codeSigning MUST be present",
		Citation:      "BRs: 7.1.2.3.f",
		Source:        MinimumRequirementsForCodeSigningCertificates,
		EffectiveDate: util.MRfCSCEffectiveDate,
		Lint:          &subCertExtKeyUsageCodeSigningNotSet{},
	})
}
