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

/**********************************************************************************************************************
Added by: gbb823

Referenced from: BRfCSC v3.4
First seen: MRfCSC

Certificate Field: subject:countryName (OID: 2.5.4.6)
Required/Optional: Required
Contents:   The subject:countryName MUST contain the two‐letter ISO 3166‐1 country
			code associated with the location of the Subject verified under BR Section 3.2.2.3. If a Country
			is not represented by an official ISO 3166‐1 country code, the CA MAY specify the ISO 3166‐1
			user‐assigned code of XX indicating that an official ISO 3166‐1 alpha‐2 code has not been
			assigned.
**********************************************************************************************************************/

import (
	"strings"

	"github.com/moa-lab/code-signing-certs-lint/tree/main/glint/util"
	"github.com/zmap/zcrypto/x509"
)

type countryNotIso struct{}

func (l *countryNotIso) Initialize() error {
	return nil
}

func (l *countryNotIso) CheckApplies(c *x509.Certificate) bool {
	return util.IsSubscriberCert(c)
}

func (l *countryNotIso) Execute(c *x509.Certificate) *LintResult {
	for _, j := range c.Subject.Country {
		if !util.IsISOCountryCode(strings.ToUpper(j)) {
			return &LintResult{Status: Error}
		}
	}
	return &LintResult{Status: Pass}
}

func init() {
	RegisterLint(&Lint{
		Name:          "e_subject_country_not_iso",
		Description:   "Subject name fields must not contain '.','-',' ' or any other indication that the field has been omitted",
		Citation:      "BRfCSC v2.0",
		Source:        BRfCSCV20,
		EffectiveDate: util.MRfCSCEffectiveDate,
		Lint:          &countryNotIso{},
	})
}
