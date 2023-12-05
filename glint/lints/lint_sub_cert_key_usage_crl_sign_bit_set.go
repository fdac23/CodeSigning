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

type subCertKeyUsageCrlBitSet struct{}

/******************************************************************************
Added by: gbb823

Referenced from: BRfCSC v3.4
First seen: MRfCSC v1.1

7.1.2.3.e keyUsage
	This extension MUST be present and MUST be marked critical.

	The bit position for digitalSignature MUST be set. Bit positions for
	keyCertSign and cRLSign MUST NOT be set. All other bit positions SHOULD
	NOT be set.
******************************************************************************/

func (l *subCertKeyUsageCrlBitSet) Initialize() error {
	return nil
}

func (l *subCertKeyUsageCrlBitSet) CheckApplies(c *x509.Certificate) bool {
	return util.IsSubscriberCert(c) && util.IsExtInCert(c, util.KeyUsageOID)
}

func (l *subCertKeyUsageCrlBitSet) Execute(c *x509.Certificate) *LintResult {
	if (c.KeyUsage & x509.KeyUsageCRLSign) == x509.KeyUsageCRLSign {
		return &LintResult{Status: Error}
	} else {
		return &LintResult{Status: Pass}
	}
}

func init() {
	RegisterLint(&Lint{
		Name:          "e_sub_cert_key_usage_crl_sign_bit_set",
		Description:   "Subscriber Certificate: keyUsage The bit position for cRLSign MUST NOT be set.",
		Citation:      "BRs: 7.1.2.3.e",
		Source:        MinimumRequirementsForCodeSigningCertificates,
		EffectiveDate: util.MRfCSCEffectiveDate,
		Lint:          &subCertKeyUsageCrlBitSet{},
	})
}
