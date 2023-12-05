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
BRfCSC v2.0: 9.2.5.d
As specified in Section 9.2.5 of the EV Guidelines
************************************************/

/************************************************
CA-Browser Forum EV Guidelines
v1.7.3: 9.2.5
9.2.5. Subject Registration Number Field
Certificate field: Subject:serialNumber (OID: 2.5.4.5)
EV Guidelines, v. 1.7.3 12
Required/Optional: Required
Contents: For Private Organizations, this field MUST contain
the Registration (or similar) Number assigned to the Subject
by the Incorporating or Registration Agency in its Jurisdiction
of Incorporation or Registration, as appropriate. If the
Jurisdiction of Incorporation or Registration does not provide
a Registration Number, then the date of Incorporation or
Registration SHALL be entered into this field in any one of the
common date formats. For Government Entities that do not have a
Registration Number or readily verifiable date of creation, the CA
SHALL enter appropriate language to indicate that the Subject is a
Government Entity. For Business Entities, the Registration Number
that was received by the Business Entity upon government registration
SHALL be entered in this field. For those Business Entities that register
with an Incorporating Agency or Registration Agency in a jurisdiction
that does not issue numbers pursuant to government registration, the date of
the registration SHALL be entered into this field in any one of the common
date formats. Effective as of 1 October 2020, if the CA has disclosed a
set of acceptable format or formats for Registration Numbers for the
applicable Registration Agency or Incorporating Agency, as described in
Section 11.1.3, the CA MUST ensure, prior to issuance, that the Registration
Number is valid according to at least one currently disclosed format
for that applicable Registration Agency or Incorporating agency.
************************************************/
import (
	"github.com/moa-lab/code-signing-certs-lint/tree/main/glint/util"
	"github.com/zmap/zcrypto/x509"
)

type evSNMissing struct{}

func (l *evSNMissing) Initialize() error {
	return nil
}

func (l *evSNMissing) CheckApplies(c *x509.Certificate) bool {
	return util.IsEV(c.PolicyIdentifiers) && util.IsSubscriberCert(c)
}

func (l *evSNMissing) Execute(c *x509.Certificate) *LintResult {
	if len(c.Subject.SerialNumber) == 0 {
		return &LintResult{Status: Error}
	}
	return &LintResult{Status: Pass}
}

func init() {
	RegisterLint(&Lint{
		Name:          "e_ev_serial_number_missing",
		Description:   "EV certificates must include serialNumber in subject",
		Citation:      "BRfCSCV20: 9.2.5.d",
		Source:        BRfCSCV20,
		EffectiveDate: util.BRfCSCV20EffectiveDate,
		Lint:          &evSNMissing{},
	})
}
