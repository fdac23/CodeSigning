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
	"encoding/asn1"

	"github.com/moa-lab/code-signing-certs-lint/tree/main/glint/util"
	"github.com/zmap/zcrypto/x509"
)

type subCertNotCa struct{}

type basicConstraints struct {
	IsCA       bool `asn1:"optional"`
	MaxPathLen int  `asn1:"optional,default:-1"`
}

/******************************************************************************
Added by: gbb823

Referenced from: BRfCSC v3.4
First seen: MRfCSC v1.1

7.1.2.3.b cRLDistributionPoints
	This extension MUST be present. It MUST Not be marked critical, and it MUST contain the HTTP URL of
	the CA's CRL service.
******************************************************************************/

func (l *subCertNotCa) Initialize() error {
	return nil
}

func (l *subCertNotCa) CheckApplies(c *x509.Certificate) bool {
	return util.IsSubscriberCert(c) && util.IsExtInCert(c, util.KeyUsageOID) && c.KeyUsage&x509.KeyUsageCertSign == 0 && util.IsExtInCert(c, util.BasicConstOID)
}

func (l *subCertNotCa) Execute(c *x509.Certificate) *LintResult {
	e := util.GetExtFromCert(c, util.BasicConstOID)
	var constraints basicConstraints
	if _, err := asn1.Unmarshal(e.Value, &constraints); err != nil {
		return &LintResult{Status: Fatal}
	}
	if constraints.IsCA {
		return &LintResult{Status: Error}
	} else {
		return &LintResult{Status: Pass}
	}
}

func init() {
	RegisterLint(&Lint{
		Name:          "e_sub_cert_is_ca",
		Description:   "Subscriber Certificate: basicContrainsts cA field MUST NOT be true.",
		Citation:      "BRs: 7.1.2.3.d",
		Source:        MinimumRequirementsForCodeSigningCertificates,
		EffectiveDate: util.MRfCSCEffectiveDate,
		Lint:          &subCertNotCa{},
	})
}
