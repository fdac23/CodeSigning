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

type authorityKeyIdNoKeyIdField struct{}

/************************************************
BRfCSC v3.4:

7.1.2.3.g
	This extension MUST be present and MUST NOT be marked critical.

Requirement Derived From RFC 2459:
 ************************************************/

func init() {
	RegisterLint(&Lint{
		Name:          "e_ext_authority_key_identifier_no_key_identifier",
		Description:   "CAs must include keyIdentifer field of AKI in all non-self-issued certificates",
		Citation:      "RFC 5280: 4.2.1.1",
		Source:        MinimumRequirementsForCodeSigningCertificates,
		EffectiveDate: util.MRfCSCEffectiveDate,
		Lint:          &authorityKeyIdNoKeyIdField{},
	})
}

func (l *authorityKeyIdNoKeyIdField) Initialize() error {
	return nil
}

func (l *authorityKeyIdNoKeyIdField) CheckApplies(c *x509.Certificate) bool {
	return util.IsSubscriberCert(c)
}

func (l *authorityKeyIdNoKeyIdField) Execute(c *x509.Certificate) *LintResult {
	if c.AuthorityKeyId != nil || util.IsCACert(c) && util.IsSelfSigned(c) {
		return &LintResult{Status: Pass}
	} else {
		return &LintResult{Status: Error}
	}
}
