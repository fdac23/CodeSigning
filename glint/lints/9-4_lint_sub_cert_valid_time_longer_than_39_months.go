package lints

/*
 * ZLint Copyright 2017 Regents of the University of Michigan
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
MRfCSC: 9.4
Subscribers and Signing Authorities MAY sign Code at
any point in the development or distribution process.
Code Signatures may be verified at any time, including
during download, unpacking, installation, reinstallation,
or execution, or during a forensic investigation. The
validity period for a Code Signing Certificate issued
to a Subscriber or Signing Service MUST NOT exceed 39
months. The Timestamp Authority MUST use a new Timestamp
Certificate with a new private key no later than every
15 months to minimize the impact to users in the event
that a Timestamp Certificate's private key is compromised.
The validity for a Time Stamp Certificate must not exceed
135 months. The Timestamp Certificate MUST meet the
"Minimum Cryptographic Algorithm and Key Size
Requirements" in Appendix A for the communicated time period.
************************************************/
/************************************************
BR 1.4.1: 6.3.2
Subscriber	Certificates	issued	after	the	Effective
Date	MUST	have	a	Validity	Period	no	greater
than	60	months.	Except	as	provided	for	below,	Subscriber
Certificates	issued	after	1	April	2015	MUST
have	a	Validity	Period	no	greater	than	39	months.
Until	30	June	2016,	CAs	MAY	continue	to	issue
Subscriber	Certificates	with	a	Validity	Period
greater	than	39	months	but	not	greater	than	60
months	provided	that	the	CA	documents	that	the
Certificate	is	for	a	system	or	software	that:
(a) was	in	use	prior	to	the	Effective	Date;
(b) is	currently	in	use	by	either	the	Applicant	or
a	substantial	number	of	Relying	Parties;
(c) fails	to	operate	if	the	Validity	Period	is	shorter	than	60	months;
(d) does	not	contain	known	security	risks	to	Relying	Parties;	and
(e) is	difficult	to	patch	or	replace	without	substantial	economic	outlay
************************************************/

import (
	"github.com/moa-lab/code-signing-certs-lint/tree/main/glint/util"
	"github.com/zmap/zcrypto/x509"
)

type subCertValidTimeLongerThan39Months struct{}

func (l *subCertValidTimeLongerThan39Months) Initialize() error {
	return nil
}

func (l *subCertValidTimeLongerThan39Months) CheckApplies(c *x509.Certificate) bool {
	return util.IsSubscriberCert(c)
}

func (l *subCertValidTimeLongerThan39Months) Execute(c *x509.Certificate) *LintResult {
	if c.NotBefore.AddDate(0, 39, 0).Before(c.NotAfter) {
		return &LintResult{Status: Error}
	}
	return &LintResult{Status: Pass}
}

func init() {
	RegisterLint(&Lint{
		Name:          "e_sub_cert_valid_time_longer_than_39_months",
		Description:   "Subscriber Certificates issued after 1 July 2016 but prior to 1 March 2018 MUST have a Validity Period no greater than 39 months.",
		Citation:      "MRfCSC: 6.3.2",
		Source:        MinimumRequirementsForCodeSigningCertificates,
		EffectiveDate: util.SubCert39Month, // July 2 2016
		Lint:          &subCertValidTimeLongerThan39Months{},
	})
}
