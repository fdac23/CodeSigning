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

type subCertAiaMissing struct{}

/******************************************************************************
Added by: gbb823

Referenced from: BRfCSC v3.4
First seen: MRfCSC v1.1

7.1.2.3.c authorityInformationAccess
	This extension MUST be present. It MUST NOT be marked critical.

	It MUST contain the HTTP URL of the Issuing CA’s certificate (accessMethod =
	1.3.6.1.5.5.7.48.2). If the CA provides OCSP responses, it MUST contain the HTTP
	URL of the Issuing CA’s OCSP responder (accessMethod = 1.3.6.1.5.5.7.48.1).
******************************************************************************/

func (l *subCertAiaMissing) Initialize() error {
	return nil
}

func (l *subCertAiaMissing) CheckApplies(c *x509.Certificate) bool {
	return util.IsSubscriberCert(c)
}

func (l *subCertAiaMissing) Execute(c *x509.Certificate) *LintResult {
	if util.IsExtInCert(c, util.AiaOID) {
		return &LintResult{Status: Pass}
	} else {
		return &LintResult{Status: Error}
	}
}

func init() {
	RegisterLint(&Lint{
		Name:          "e_sub_cert_aia_missing",
		Description:   "Subscriber Certificate: authorityInformationAccess This extension MUST be present. It MUST NOT be marked critical.",
		Citation:      "BRs: 7.1.2.3.c",
		Source:        MinimumRequirementsForCodeSigningCertificates,
		EffectiveDate: util.MRfCSCEffectiveDate,
		Lint:          &subCertAiaMissing{},
	})
}
