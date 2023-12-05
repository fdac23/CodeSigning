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

/************************************************
BRfCSC v3.4:

7.1.1 Version number(s)
	Certificates MUST be of type X.509  v3.

Requirement Derived From RFC 2459:

4.1.2.1.  Version
   This field describes the version of the encoded certificate. When
   extensions are used, as expected in this profile, version MUST be 3
   (value is 2). If no extensions are present, but a UniqueIdentifier
   is present, the version SHOULD be 2 (value is 1); however, the version
   MAY be 3.  If only basic fields are present, the version SHOULD be 1
   (the value is omitted from the certificate as the default value);
   however, the version MAY be 2 or 3.

   Implementations SHOULD be prepared to accept any version certificate.
   At a minimum, conforming implementations MUST recognize version 3 certificates.
 ************************************************/

type certExtensionsVersionNot3 struct{}

func (l *certExtensionsVersionNot3) Initialize() error {
	return nil
}

func (l *certExtensionsVersionNot3) CheckApplies(cert *x509.Certificate) bool {
	return util.IsSubscriberCert(cert)
}

func (l *certExtensionsVersionNot3) Execute(cert *x509.Certificate) *LintResult {
	/*
	 *	Check if the cert vesion is 3. Note this value is not zero index as specified in RFC 2459
	 */
	if cert.Version != 3 {
		return &LintResult{Status: Error}
	}
	return &LintResult{Status: Pass}
}

func init() {
	RegisterLint(&Lint{
		Name:        "e_cert_extensions_version_not_3",
		Description: "Certificates MUST be of type X.509 v3.",
		Citation:    "MRfCSC: 7.1.1",
		Source:      MinimumRequirementsForCodeSigningCertificates,

		/*
		 *	Note that the effective date chosen for this lint is in line with RFC2459 as this
		 *  was the original requirement date.
		 */
		EffectiveDate: util.RFC2459Date,
		Lint:          &certExtensionsVersionNot3{},
	})
}
