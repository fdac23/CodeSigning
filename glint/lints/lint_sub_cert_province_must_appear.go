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
MRfCSC: 9.2.4.d
Certificate Field: subject:stateOrProvinceName (OID: 2.5.4.8)
Required/Optional: Required if the subject:localityName field is absent.
Optional if thesubject:localityName field is present
Contents: If present, the subject:stateOrProvinceName field MUST contain
 the Subject’s state or province information as verified under BR Section
  3.2.2.1 or 3.2.3. If the subject:countryName field specifies the ISO
  3166-1 user-assigned code of XX in accordance with BR Section 7.1.4.2.2.g.,
   the subject:stateOrProvinceName field MAY contain the full name of the
   Subject’s country information as verified under BR Section 3.2.2.3
 ***************************************************************/

import (
	"github.com/moa-lab/code-signing-certs-lint/tree/main/glint/util"
	"github.com/zmap/zcrypto/x509"
)

type subCertProvinceMustAppear struct{}

func (l *subCertProvinceMustAppear) Initialize() error {
	return nil
}

func (l *subCertProvinceMustAppear) CheckApplies(c *x509.Certificate) bool {
	return util.IsSubscriberCert(c)
}

func (l *subCertProvinceMustAppear) Execute(c *x509.Certificate) *LintResult {
	if !util.TypeInName(&c.Subject, util.StateOrProvinceNameOID) && !util.TypeInName(&c.Subject, util.LocalityNameOID) {
		return &LintResult{Status: Error}
	} else {
		return &LintResult{Status: Pass}
	}
}

func init() {
	RegisterLint(&Lint{
		Name:          "e_subscriber_certificate_province_must_appear",
		Description:   "Subscriber Certificate: subject:stateOrProvinceName MUST appear if the subject:localityName is absent",
		Citation:      "MRfCSC: 9.2.4.d",
		Source:        MinimumRequirementsForCodeSigningCertificates,
		EffectiveDate: util.MRfCSCEffectiveDate,
		Lint:          &subCertProvinceMustAppear{},
	})
}
