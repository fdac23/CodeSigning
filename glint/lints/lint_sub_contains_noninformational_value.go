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

/**********************************************************************************************************************
 BRfCSC v2.0 : As specified in BR Section 7.1.4.2.2.j. Subject attributes MUST NOT contain only metadata
 such as ‘.’, ‘-‘, and ‘ ‘ (i.e. space) characters, and/or any other indication that the value is absent,
 incomplete, or not applicable.
**********************************************************************************************************************/

import (
	"strings"

	"github.com/moa-lab/code-signing-certs-lint/tree/main/glint/util"
	"github.com/zmap/zcrypto/x509"
)

type illegalChar struct{}

func (l *illegalChar) Initialize() error {
	return nil
}

func (l *illegalChar) CheckApplies(c *x509.Certificate) bool {
	return util.IsSubscriberCert(c)
}

func (l *illegalChar) Execute(c *x509.Certificate) *LintResult {
	domain := c.Subject.DomainComponent
	serial := c.Subject.SerialNumber
	names := c.Subject.Names
	for _, j := range names {
		tempStr, ok := j.Value.(string)
		if !ok {
			continue //TODO: change this?
		}
		if tempStr == "-" || tempStr == "." || tempStr == " " {
			return &LintResult{Status: Error}
		}
	}
	if serial == "-" || serial == "." || serial == " " {
		return &LintResult{Status: Error}
	}
	for _, j := range domain {
		if strings.Compare(j, "-") == 0 ||
			strings.Compare(j, ".") == 0 ||
			strings.Compare(j, " ") == 0 {
			return &LintResult{Status: Error}
		}
	}
	return &LintResult{Status: Pass}
}

func init() {
	RegisterLint(&Lint{
		Name:          "e_subject_contains_noninformational_value",
		Description:   "Subject name fields must not contain '.','-',' ' or any other indication that the field has been omitted",
		Citation:      "BRfCSC v2.0",
		Source:        BRfCSCV20,
		EffectiveDate: util.BRfCSCV20EffectiveDate,
		Lint:          &illegalChar{},
	})
}
