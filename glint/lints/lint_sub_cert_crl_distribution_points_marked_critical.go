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

type subCertDistPointsMarkedCrit struct{}

/******************************************************************************
Added by: gbb823

Referenced from: BRfCSC v3.4
First seen: MRfCSC v1.1

7.1.2.3.b cRLDistributionPoints
	This extension MUST be present. It MUST Not be marked critical, and it MUST contain the HTTP URL of
	the CA's CRL service.
******************************************************************************/

func (l *subCertDistPointsMarkedCrit) Initialize() error {
	return nil
}

func (l *subCertDistPointsMarkedCrit) CheckApplies(c *x509.Certificate) bool {
	return util.IsSubscriberCert(c) && util.IsExtInCert(c, util.CrlDistOID)
}

func (l *subCertDistPointsMarkedCrit) Execute(c *x509.Certificate) *LintResult {
	e := util.GetExtFromCert(c, util.CrlDistOID)
	if !e.Critical {
		return &LintResult{Status: Pass}
	} else {
		return &LintResult{Status: Error}
	}
}

func init() {
	RegisterLint(&Lint{
		Name:          "e_sub_cert_crl_destribution_points_marked_critical",
		Description:   "Subscriber Certificate: cRLDistributionPoints MUST be present and SHOULD NOT be marked critical.",
		Citation:      "BRs: 7.1.2.3.b",
		Source:        MinimumRequirementsForCodeSigningCertificates,
		EffectiveDate: util.MRfCSCEffectiveDate,
		Lint:          &subCertDistPointsMarkedCrit{},
	})
}
