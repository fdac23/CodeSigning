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
MRfCSC: 9.2.4.f
Certificate Field: subject:countryName (OID: 2.5.4.6)
Required/Optional: Required
Contents: The subject:countryName MUST contain the two-letter
 ISO 3166-1 country code associated with the location of the
  Subject verified under BR Section 3.2.2.3. If a Country is
  not represented by an official ISO 3166-1 country code, the
  CA MAY specify the ISO 3166-1 user-assigned code of XX
  indicating that an official ISO 3166-1 alpha-2 code has not
  been assigned
***************************************************************/
import (
	"github.com/moa-lab/code-signing-certs-lint/tree/main/glint/util"
	"github.com/zmap/zcrypto/x509"
)

type subCertCountryNameMustAppear struct{}

func (l *subCertCountryNameMustAppear) Initialize() error {
	return nil
}

func (l *subCertCountryNameMustAppear) CheckApplies(c *x509.Certificate) bool {
	return util.IsSubscriberCert(c)
}

func (l *subCertCountryNameMustAppear) Execute(c *x509.Certificate) *LintResult {
	if len(c.Subject.Country) == 0 {
		return &LintResult{Status: Error}
	}

	return &LintResult{Status: Pass}
}

func init() {
	RegisterLint(&Lint{
		Name:          "e_subscriber_certificate_country_name_must_appear",
		Description:   "Subscriber Certificate: subject:countryName MUST appear",
		Citation:      "MRfCSC: 9.2.4.f",
		Source:        MinimumRequirementsForCodeSigningCertificates,
		EffectiveDate: util.MRfCSCEffectiveDate,
		Lint:          &subCertCountryNameMustAppear{},
	})
}
