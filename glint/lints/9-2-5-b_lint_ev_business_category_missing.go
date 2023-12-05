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
/************************************************
BRfCSC v2.0: 9.2.5.b
As specified in Section 9.2.3 of the EV Guidelines
************************************************/

/************************************************
CA-Browser Forum EV Guidelines
v1.7.3: 9.2.3
9.2.3. Subject Business Category Field
Certificate field: subject:businessCategory (OID: 2.5.4.15)
Required/Optional: Required
Contents: This field MUST contain one of the following strings:
"Private Organization", "Government Entity", "Business Entity",
or "Non-Commercial Entity" depending upon whether the Subject
qualifies under the terms of Section 8.5.2,8.5.3, 8.5.4 or 8.5.5
of these Guidelines, respectively.
************************************************/
import (
	"github.com/moa-lab/code-signing-certs-lint/tree/main/glint/util"
	"github.com/zmap/zcrypto/x509"
)

type evNoBiz struct{}

func (l *evNoBiz) Initialize() error {
	return nil
}

func (l *evNoBiz) CheckApplies(c *x509.Certificate) bool {
	return util.IsEV(c.PolicyIdentifiers) && util.IsSubscriberCert(c)
}

func (l *evNoBiz) Execute(c *x509.Certificate) *LintResult {
	if util.TypeInName(&c.Subject, util.BusinessOID) {
		return &LintResult{Status: Pass}
	} else {
		return &LintResult{Status: Error}
	}
}

func init() {
	RegisterLint(&Lint{
		Name:          "e_ev_business_category_missing",
		Description:   "EV certificates must include businessCategory in subject",
		Citation:      "BRfCSCV20: 9.2.5.b",
		Source:        BRfCSCV20,
		EffectiveDate: util.BRfCSCV20EffectiveDate,
		Lint:          &evNoBiz{},
	})
}
