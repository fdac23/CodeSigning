package lints

import (
	"encoding/asn1"

	"github.com/moa-lab/code-signing-certs-lint/tree/main/glint/util" //"fmt"
	"github.com/zmap/zcrypto/x509"
)

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
BRfCSC v2.0: 9.2.5.e
As specified in Section 9.2.6 of the EV Guidelines
************************************************/

/************************************************
CA-Browser Forum EV Guidelines
v1.7.3: 9.2.6
9.2.6. Subject Physical Address of Place of Business Field
Certificate fields:
Number and street: subject:streetAddress (OID: 2.5.4.9)
->City or town: subject:localityName (OID: 2.5.4.7)
State or province (where applicable): subject:stateOrProvinceName (OID: 2.5.4.8)
Country: subject:countryName (OID: 2.5.4.6)
Postal code: subject:postalCode (OID: 2.5.4.17)
Required/Optional: As stated in Section 7.1.4.2.2 d, e, f, g and h of the Baseline
Requirements. Contents: This field MUST contain the address of the physical location
of the Subject’s Place of Business.

************************************************/

//jurisdictionStateOrProvinceName = asn1.ObjectIdentifier{1,3,6,1,4,1,311,2,1,2}
//jurisdictionCountryName = asn1.ObjectIdentifier{1,3,6,1,4,1,311,2,1,3}

type evJurisdictionMissing struct{}

func (l *evJurisdictionMissing) Initialize() error {
	return nil
}

func (l *evJurisdictionMissing) CheckApplies(c *x509.Certificate) bool {
	return util.IsEV(c.PolicyIdentifiers) && util.IsSubscriberCert(c)
}

func (l *evJurisdictionMissing) Execute(c *x509.Certificate) *LintResult {
	jurisdictionLocalityNameOID := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 60, 2, 1, 1}
	jurisdictionStateOrProvinceName := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 60, 2, 1, 2}
	jurisdictionCountryName := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 60, 2, 1, 3}
	//fmt.Println(&c.Subject)
	//fmt.Println("Country")
	//fmt.Println(util.TypeInName(&c.Subject, jurisdictionCountryName))
	////fmt.Println("State Or Province")
	//fmt.Println(util.TypeInName(&c.Subject, jurisdictionStateOrProvinceName))
	//fmt.Println("Locality")
	//fmt.Println(util.TypeInName(&c.Subject, jurisdictionLocalityNameOID))
	if util.TypeInName(&c.Subject, jurisdictionLocalityNameOID) && util.TypeInName(&c.Subject, jurisdictionStateOrProvinceName) && util.TypeInName(&c.Subject, jurisdictionCountryName) {
		return &LintResult{Status: Pass}
	} else if !util.TypeInName(&c.Subject, jurisdictionLocalityNameOID) && util.TypeInName(&c.Subject, jurisdictionStateOrProvinceName) && util.TypeInName(&c.Subject, jurisdictionCountryName) {
		return &LintResult{Status: Pass}
	} else if !util.TypeInName(&c.Subject, jurisdictionLocalityNameOID) && !util.TypeInName(&c.Subject, jurisdictionStateOrProvinceName) && util.TypeInName(&c.Subject, jurisdictionCountryName) {
		return &LintResult{Status: Pass}
	} else {
		return &LintResult{Status: Error}
	}
}

func init() {
	RegisterLint(&Lint{
		Name:          "e_ev_jurisdiction_missing",
		Description:   "The certificate MUST contain the Jurisdiction the certificate was issued in",
		Citation:      "BRfCSCV20: 9.2.5.c",
		Source:        BRfCSCV20,
		EffectiveDate: util.BRfCSCV20EffectiveDate,
		Lint:          &evJurisdictionMissing{},
	})
}
