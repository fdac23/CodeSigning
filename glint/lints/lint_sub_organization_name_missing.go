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
MRfCSC: 9.2.4.a
Certificate Field: subject:organizationName (OID 2.5.4.10)
Required/Optional: Required
Contents: The subject:organizationName field MUST contain either
 the Subject’s name or DBA as verified under BR Section 3.2. The
  CA MAY include information in this field that differs slightly
  from the verified name, such as common variations or
  abbreviations, provided that the CA documents the difference
  and any abbreviations used are locally accepted abbreviations;
  e.g., if the official record shows “Company Name Incorporated”,
   the CA MAY use “Company Name Inc.” or “Company Name”. Because
   subject name attributes for individuals
   (e.g. givenName (2.5.4.42) and surname (2.5.4.4)) are not
   broadly supported by application software, the CA MAY use the
    subject:organizationName field to convey a natural person
    Subject’s name or DBA. The CA MUST have a documented process
     for verifying that the information included in the
     subject:organizationName field is not misleading to a Relying Party
***************************************************************/

import (
	"github.com/moa-lab/code-signing-certs-lint/tree/main/glint/util"
	"github.com/zmap/zcrypto/x509"
)

type subjectOrganizationName struct{}

func (l *subjectOrganizationName) Initialize() error {
	return nil
}

func (l *subjectOrganizationName) CheckApplies(c *x509.Certificate) bool {
	return util.IsSubscriberCert(c)
}

func (l *subjectOrganizationName) Execute(c *x509.Certificate) *LintResult {
	if len(c.Subject.Organization) != 0 {
		return &LintResult{Status: Pass}
	} else {
		return &LintResult{Status: Error}
	}
}

func init() {
	RegisterLint(&Lint{
		Name:          "e_subject_organization_name_missing",
		Description:   "Subscriber Certificate: organizationName is required.",
		Citation:      "MRfCSC: 9.2.4.a",
		Source:        MinimumRequirementsForCodeSigningCertificates,
		EffectiveDate: util.MRfCSCEffectiveDate,
		Lint:          &subjectOrganizationName{},
	})
}
