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
{MRfCSC, BRfCSC v1.2}: 9.1
As specified in BR Section 7.1.4.1.
************************************************/

/************************************************
CA-Browser Forum Baseline Requirements
v.{ 1.4.1, 1.6.5}: 7.1.4.1
The	content	of	the	Certificate	Issuer
Distinguished	Name	field	MUST	match	the
Subject	DN	of	the	Issuing	CA	to	support
Name	chaining	as	specified	in	RFC
5280,	section	4.1.2.4.
************************************************/

/************************************************
RFC 5280: 4.1.2.4
The issuer field identifies the entity that has signed and issued the
   certificate.  The issuer field MUST contain a non-empty distinguished
   name (DN).  The issuer field is defined as the X.501 type Name
   [X.501].
************************************************/

/************************************************
CA-Browser Forum Baseline Requirements
v.{1.7.1, 1.7.3, 1.7.4}: 7.1.4.1
Prior to 2020-09-30, the content of the Certificate Issuer Distinguished Name field MUST
match the Subject DN of the Issuing CA to support Name chaining as specified in RFC 5280,
section 4.1.2.4.

Effective 2020-09-30, the following requirements SHOULD be met by all newly-issued
Subordinate CA Certificates that are not used to issue TLS certificates, as defined in Section
7.1.2.2, and MUST be met for all other Certificates, regardless of whether the Certificate is a
CA Certificate or a Subscriber Certificate.
For every valid Certification Path (as defined by RFC 5280, Section 6):
• For each Certificate in the Certification Path, the encoded content of the Issuer Distinguished
Name field of a Certificate SHALL be byte-for-byte identical with the encoded form of the
Subject Distinguished Name field of the Issuing CA certificate.
• For each CA Certificate in the Certification Path, the encoded content of the Subject
Distinguished Name field of a Certificate SHALL be byte-for-byte identical among all
Certificates whose Subject Distinguished Names can be compared as equal according to RFC
5280, Section 7.1, and including expired and revoked Certificates.

************************************************/

import (
	"fmt"
	"time"

	"github.com/moa-lab/code-signing-certs-lint/tree/main/glint/util"
	"github.com/zmap/zcrypto/x509"
)

type certChain struct {
	Inter [][]byte `json:"inter"`
	Root  []byte   `json:"root"`
	Leaf  []byte   `json:"leaf"`
	Error string   `json:"error"`
}

type issuerFieldEmpty struct{}

func (l *issuerFieldEmpty) Initialize() error {
	return nil
}

func (l *issuerFieldEmpty) CheckApplies(c *x509.Certificate) bool {
	return util.IsSubscriberCert(c)
}

func (l *issuerFieldEmpty) Execute(c *x509.Certificate) *LintResult {
	//Prior to 2020-9-30 do this
	if util.NameEncodingChange.After(c.NotBefore) {
		if &c.Issuer != nil && util.NotAllNameFieldsAreEmpty(&c.Issuer) {
			return &LintResult{Status: Pass}
		} else {
			return &LintResult{Status: Error}
		}
		//As of 2020-9-30, look at the chain
	} else {
		issueTime := c.NotBefore
		currentTime := time.Date(issueTime.Year(), issueTime.Month(), issueTime.Day()+1, 0, 0, 0, 0, time.UTC)
		opts := x509.VerifyOptions{
			CurrentTime:   currentTime,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
			Intermediates: x509.NewCertPool(),
		}

		issuedDName := c.Issuer
		certChains, err, _, _ := c.Verify(opts)
		if err != nil {
			fmt.Println("Verification error", err)
			return &LintResult{Status: Warn} //This shouldn't be returned
		}
		for _, chain := range certChains {
			for _, higher := range chain {
				fmt.Println(higher.Subject)
				fmt.Println(issuedDName)
				//if(higher.Subject != issuedDName) {
				//	return &LintResult{Status: Error}
				//}
				issuedDName = higher.Issuer
			}
		}
		return &LintResult{Status: Pass}
	}
}

func init() {
	RegisterLint(&Lint{
		Name:          "e_issuer_field_empty",
		Description:   "Certificate issuer field MUST NOT be empty and must have a non-empty distingushed name",
		Citation:      "RFC 5280: 4.1.2.4",
		Source:        RFC5280,
		EffectiveDate: util.RFC5280Date,
		Lint:          &issuerFieldEmpty{},
	})
}
