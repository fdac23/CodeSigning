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
BRfCSC v2.0: 9.2.5.a
As specified in Section 9.2.1 of the EV Guidelines
************************************************/

/************************************************
CA-Browser Forum EV Guidelines
v1.7.3: 9.2.1
9.2.1. Subject Organization Name Field
Certificate field: subject:organizationName (OID 2.5.4.10 )
Required/Optional: Required
Contents: This field MUST contain the Subject’s full legal organization
name as listed in the official records of the Incorporating or Registration
Agency in the Subject’s Jurisdiction of Incorporation or Registration or as
otherwise verified by the CA as provided herein. A CA MAY abbreviate the
organization prefixes or suffixes in the organization name, e.g.,if the official
record shows “Company Name Incorporated” the CA MAY include “Company Name, Inc.”
When abbreviating a Subject’s full legal name as allowed by this subsection, the
CA MUST use abbreviations that are not misleading in the Jurisdiction of Incorporation
or Registration.In addition, an assumed name or DBA name used by the Subject MAY be
included at the beginning of this field, provided that it is followed by the full legal
organization name in parenthesis.If the combination of names or the organization name by
itself exceeds 64 characters, the CA MAY abbreviate parts of the organization name, and/or
omit non-material words in the organization name in such a way that the text in this field
does not exceed the 64-character limit; provided that the CA checks this field in accordance
with section 11.12.1 and a Relying Party will not be misled into thinking that they
are dealing with a different organization. In cases where this is notpossible, the
CA MUST NOT issue the EV Certificate.
************************************************/

import (
	"github.com/moa-lab/code-signing-certs-lint/tree/main/glint/util"
	"github.com/zmap/zcrypto/x509"
)

type evOrgMissing struct{}

func (l *evOrgMissing) Initialize() error {
	return nil
}

func (l *evOrgMissing) CheckApplies(c *x509.Certificate) bool {
	return util.IsEV(c.PolicyIdentifiers) && util.IsSubscriberCert(c)
}

func (l *evOrgMissing) Execute(c *x509.Certificate) *LintResult {
	if util.TypeInName(&c.Subject, util.OrganizationNameOID) {
		return &LintResult{Status: Pass}
	} else {
		return &LintResult{Status: Error}
	}
}

func init() {
	RegisterLint(&Lint{
		Name:          "e_ev_organization_name_missing",
		Description:   "EV certificates must include organizationName in subject",
		Citation:      "BRfCSCV20: 9.2.5.a",
		Source:        BRfCSCV20,
		EffectiveDate: util.BRfCSCV20EffectiveDate,
		Lint:          &evOrgMissing{},
	})
}
