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
Added by: Unknown; Updated by: gbb823

Referenced from: BRfCSC v3.4
First seen: MRfCSC

MRfCSC: 9.2.3
	This field MUST not be present in a Code Signing Certificate (Both EV and Non-EV)

BRfCSC v2.0: 9.2.3
	For Non-EV Code Signing Certificates, this field MUST not be present in a Code Signing Certificate. (Only Non-EV)

BRfCSC v2.2: 9.2.3
	This field MUST not be present in a Code Signing Certificate. (Both EV and Non-EV)

***************************************************************/

import (
	"github.com/moa-lab/code-signing-certs-lint/tree/main/glint/util"
	"github.com/zmap/zcrypto/x509"
)

type subjectDomainComponent struct{}

func (l *subjectDomainComponent) Initialize() error {
	return nil
}

func (l *subjectDomainComponent) CheckApplies(c *x509.Certificate) bool {
	return util.IsSubscriberCert(c)
}

func (l *subjectDomainComponent) Execute(c *x509.Certificate) *LintResult {
	//If the certificate was before BRfCSC2.0
	if util.BRfCSCV20EffectiveDate.After(c.NotBefore) {
		if len(c.Subject.DomainComponent) == 0 {
			return &LintResult{Status: Pass}
		} else {
			return &LintResult{Status: Error}
		}
	}
	//If the certificate was issued on or after BRfCSC2.0 but before BRfCSC2.2
	if !util.BRfCSCV20EffectiveDate.After(c.NotBefore) && util.BRfCSCV22EffectiveDate.After(c.NotBefore) {
		if len(c.Subject.DomainComponent) == 0 {
			return &LintResult{Status: Pass}
		} else {
			if util.IsEV(c.PolicyIdentifiers) {
				return &LintResult{Status: Pass}
			} else {
				return &LintResult{Status: Error}
			}
		}
	}
	//If the certificate was issued on or after BRfCSC2.2
	if !util.BRfCSCV22EffectiveDate.After(c.NotBefore) && util.BRfCSCV20EffectiveDate.After(c.NotBefore) {
		if len(c.Subject.DomainComponent) == 0 {
			return &LintResult{Status: Pass}
		} else {
			return &LintResult{Status: Error}
		}
	} else {
		//Certificate issued before MRfCSC
		//This should never be returned
		return &LintResult{Status: Warn}
	}
}

func init() {
	RegisterLint(&Lint{
		Name:          "e_subject_domain_component_included",
		Description:   "This field must not be present in a Code Signing Certificate",
		Citation:      "MRfCSC: 9.2.3",
		Source:        MinimumRequirementsForCodeSigningCertificates,
		EffectiveDate: util.MRfCSCEffectiveDate,
		Lint:          &subjectDomainComponent{},
	})
}
