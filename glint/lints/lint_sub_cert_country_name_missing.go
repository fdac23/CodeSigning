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

type caCountryNameMissing struct{}

/******************************************************************************
Added by: jsteed

Referenced from: BRfCSC v3.4
First seen: MRfCSC v1.1

7.1.4.2.3.f
	Certificate Field: subject:countryName (OID: 2.5.4.6)
	Required/Optional: Required
	Contents: The subject:countryName MUST contain the two‐letter ISO 3166‐1 country
	code associated with the location of the Subject verified under BR Section 3.2.2.3. If a Country
	is not represented by an official ISO 3166‐1 country code, the CA MAY specify the ISO 3166‐1
	user‐assigned code of XX indicating that an official ISO 3166‐1 alpha‐2 code has not been
	assigned.
******************************************************************************/

func (l *caCountryNameMissing) Initialize() error {
	return nil
}

func (l *caCountryNameMissing) CheckApplies(c *x509.Certificate) bool {
	return util.IsSubscriberCert(c) && util.IsExtInCert(c, util.KeyUsageOID) && c.KeyUsage&x509.KeyUsageCertSign == 0 && util.IsExtInCert(c, util.BasicConstOID)
}

func (l *caCountryNameMissing) Execute(c *x509.Certificate) *LintResult {
	if c.Subject.Country != nil && c.Subject.Country[0] != "" {
		return &LintResult{Status: Pass}
	} else {
		return &LintResult{Status: Error}
	}
}

func init() {
	RegisterLint(&Lint{
		Name:          "e_sub_cert_country_name_missing",
		Description:   "The subject:countryName MUST contain the two‐letter ISO 3166‐1 country code",
		Citation:      "BRs: 7.1.4.2.3.f",
		Source:        MinimumRequirementsForCodeSigningCertificates,
		EffectiveDate: util.MRfCSCEffectiveDate,
		Lint:          &caCountryNameMissing{},
	})
}
