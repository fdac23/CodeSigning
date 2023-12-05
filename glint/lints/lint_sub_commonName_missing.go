package lints

/*
 * ZLint Copyright 2018 Regents of the University of Michigan
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

/***************************************************************
Added By: Unknown; Updated by: gbb823

Referenced from: BRfCSC v3.4
First seen: MRfCSC: 9.2.2

7.1.4.2.2 Subject distinguished name fields - EV and Non-EV Code Signing Certificates
	Certificate Field: subject:commonName (OID 2.5.4.3)
	Required/Optional: Required
	Contents: This field MUST contain the Subject’s legal name as verified under BR Section 3.2.
***************************************************************/

import (
	"github.com/moa-lab/code-signing-certs-lint/tree/main/glint/util"
	"github.com/zmap/zcrypto/x509"
)

type commonNames struct{}

func (l *commonNames) Initialize() error {
	return nil
}

func (l *commonNames) CheckApplies(c *x509.Certificate) bool {
	return util.IsSubscriberCert(c)
}

func (l *commonNames) Execute(c *x509.Certificate) *LintResult {
	if c.Subject.CommonName != "" {
		return &LintResult{Status: Pass}
	} else {
		return &LintResult{Status: Error}
	}
}

func init() {
	RegisterLint(&Lint{
		Name:          "e_subject_common_name_missing",
		Description:   "Subscriber Certificate: commonName is required.",
		Citation:      "MRfCSC: 9.2.2",
		Source:        MinimumRequirementsForCodeSigningCertificates,
		EffectiveDate: util.MRfCSCEffectiveDate,
		Lint:          &commonNames{},
	})
}
