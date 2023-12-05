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
MRfCSC: 9.3.2 & 9.6
A Root CA Certificate SHOULD NOT contain the certificatePolicies
extension.
***************************************************************/

/************************************************
BRs: 7.1.2.1c certificatePolicies
This extension SHOULD NOT be present.
************************************************/

import (
	"github.com/moa-lab/code-signing-certs-lint/tree/main/glint/util"
	"github.com/zmap/zcrypto/x509"
)

type rootCAContainsCertPolicy struct{}

func (l *rootCAContainsCertPolicy) Initialize() error {
	return nil
}

func (l *rootCAContainsCertPolicy) CheckApplies(c *x509.Certificate) bool {
	return util.IsRootCA(c)
}

func (l *rootCAContainsCertPolicy) Execute(c *x509.Certificate) *LintResult {
	if util.IsExtInCert(c, util.CertPolicyOID) {
		return &LintResult{Status: Error}
	} else {
		return &LintResult{Status: Pass}
	}
}

func init() {
	RegisterLint(&Lint{
		Name:          "e_root_ca_contains_cert_policy",
		Description:   "Root CA Certificate: certificatePolicies SHOULD NOT be present.",
		Citation:      "MRfCSC: 9.3.2",
		Source:        MinimumRequirementsForCodeSigningCertificates,
		EffectiveDate: util.MRfCSCEffectiveDate,
		Lint:          &rootCAContainsCertPolicy{},
	})
}
