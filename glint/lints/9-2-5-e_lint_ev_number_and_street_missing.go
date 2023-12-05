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
BRfCSC v2.0: 9.2.5.e
As specified in Section 9.2.6 of the EV Guidelines
************************************************/

/************************************************
CA-Browser Forum EV Guidelines
v1.7.3: 9.2.6
9.2.6. Subject Physical Address of Place of Business Field
Certificate fields:
->Number and street: subject:streetAddress (OID: 2.5.4.9)
City or town: subject:localityName (OID: 2.5.4.7)
State or province (where applicable): subject:stateOrProvinceName (OID: 2.5.4.8)
Country: subject:countryName (OID: 2.5.4.6)
Postal code: subject:postalCode (OID: 2.5.4.17)
Required/Optional: As stated in Section 7.1.4.2.2 d, e, f, g and h of the Baseline
Requirements. Contents: This field MUST contain the address of the physical location
of the Subject’s Place of Business.

************************************************/
import (
	"github.com/moa-lab/code-signing-certs-lint/tree/main/glint/util"
	"github.com/zmap/zcrypto/x509"
)

type evNumberAndStreetMissing struct{}

func (l *evNumberAndStreetMissing) Initialize() error {
	return nil
}

func (l *evNumberAndStreetMissing) CheckApplies(c *x509.Certificate) bool {
	return util.IsEV(c.PolicyIdentifiers) && util.IsSubscriberCert(c)
}

func (l *evNumberAndStreetMissing) Execute(c *x509.Certificate) *LintResult {
	if len(c.Subject.StreetAddress) == 0 {
		return &LintResult{Status: Error}
	}
	return &LintResult{Status: Pass}
}

func init() {
	RegisterLint(&Lint{
		Name:          "e_ev_Number_And_Street_Missing",
		Description:   "The certificate MUST contain the address of the physical location of the Subject’s Place of Business.",
		Citation:      "BRfCSCV20: 9.2.5.e",
		Source:        BRfCSCV20,
		EffectiveDate: util.BRfCSCV20EffectiveDate,
		Lint:          &evNumberAndStreetMissing{},
	})
}
