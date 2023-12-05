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

package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"sort"
	"strings"

	//"os/exec" Used for making database
	"database/sql"
	"strconv"

	_ "github.com/mattn/go-sqlite3"
	zlint "github.com/moa-lab/code-signing-certs-lint/tree/main/glint"
	"github.com/moa-lab/code-signing-certs-lint/tree/main/glint/lints"
	log "github.com/sirupsen/logrus"
	"github.com/zmap/zcrypto/x509"
)

var ( // flags
	listLintsJSON   bool
	listLintsSchema bool
	prettyprint     bool
	format          string
	db              *sql.DB
	err             error
)

func init() {
	flag.BoolVar(&listLintsJSON, "list-lints-json", false, "Print supported lints in JSON format, one per line")
	flag.BoolVar(&listLintsSchema, "list-lints-schema", false, "Print supported lints as a ZSchema")
	flag.StringVar(&format, "format", "der", "One of {pem, der, base64}")
	flag.BoolVar(&prettyprint, "pretty", true, "Pretty-print output")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [flags] file...\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()
	log.SetLevel(log.InfoLevel)
}

func main() {
	if listLintsJSON {
		zlint.EncodeLintDescriptionsToJSON(os.Stdout)
		return
	}
	if listLintsSchema {
		names := make([]string, 0, len(lints.Lints))
		for lintName := range lints.Lints {
			names = append(names, lintName)
		}
		sort.Strings(names)
		fmt.Printf("Lints = SubRecord({\n")
		for _, lintName := range names {
			fmt.Printf("    \"%s\":LintBool(),\n", lintName)
		}
		fmt.Printf("})\n")
		return
	}
	//Added logic to check if the results database exists, and if no creates it
	if _, err := os.Stat("./lint_results.db"); err == nil {
		db, err = sql.Open("sqlite3", "./lint_results.db") //This file MUST be present in the same directory as the executable
		//db, err = sql.Open("sqlite3", "/datasets/waltersquires1/CertificateAnalysis.db")
		if err != nil {
			panic(err)
		}
		fmt.Println("Database opened")
	} else if os.IsNotExist(err) {
		//initDB() Not currentely functional
		db, err = sql.Open("sqlite3", "./lint_results.db") //This file MUST be present in the same directory as the executable
		//db, err = sql.Open("sqlite3", "/datasets/waltersquires1/CertificateAnalysisWithLintResults.db")
		if err != nil {
			panic(err)
		}

	} else {

	}
	insertLints()
	lintFromDatabase() // Toggle to scan from dataset
	var inform = strings.ToLower(format)
	if flag.NArg() < 1 || flag.Arg(0) == "-" {
		lint(os.Stdin, inform)
	} else {
		//pathToCertificates :="/home/waltersquires1/VXUnderground_Unique_Certs/CS/"//:= flag.Arg(0)
		pathToCertificates := flag.Arg(0)
		processCertificates(pathToCertificates, inform)

	}
}

func lintFromDatabase() {
	var numberOfCertificates int
	var raw_ASN1 string
	//fmt.Println("Enter New Function")
	sourcedb := db
	//sourcedb, _ := sql.Open("sqlite3", "/datasets/waltersquires1/CertificateAnalysisWithLintResults.db") //experiment to see if i can lint from a database
	rows, err := sourcedb.Query("SELECT Count(*) FROM Certificates")
	if err != nil {
		fmt.Println("No Results // Error")
	}
	defer rows.Close()
	for rows.Next() {
		rows.Scan(&numberOfCertificates)
		fmt.Println(numberOfCertificates)
	}
	x := 1
	for x <= numberOfCertificates {
		fmt.Println(x)
		rows, err = sourcedb.Query("SELECT Raw_ASN1 FROM Certificates WHERE Certificate_ID = '" + strconv.Itoa(x) + "'")
		if err != nil {
			fmt.Println("No Results // Error")
		}
		defer rows.Close()
		for rows.Next() {
			rows.Scan(&raw_ASN1)
			//fmt.Println(raw_ASN1)
		}
		withFormatting := "-----BEGIN CERTIFICATE-----\n" + raw_ASN1 + "\n-----END CERTIFICATE-----"
		var asn1Data []byte
		p, _ := pem.Decode([]byte(withFormatting))
		asn1Data = p.Bytes
		//asn1Data = []byte(withFormatting)
		c, err := x509.ParseCertificate(asn1Data)
		if err != nil {
			fmt.Println("Could Not Parse")
			fmt.Println(err)
			//log.Fatalf("unable to parse certificate: %s", err
		} else {
			//fmt.Println("Starting to add results")
			//insertCertificate(strconv.Itoa(x), c)
			resultSet := zlint.LintCertificate(c)
			insertResults(strconv.Itoa(x), resultSet)
			//fmt.Println("Done adding Results")
		}
		x = x + 1
	}
	//fmt.Println("Exit New Fuction")
}

func lint(inputFile *os.File, inform string) bool {
	splitPath := strings.Split(inputFile.Name(), "/")
	certID := splitPath[len(splitPath)-2] + "/" + splitPath[len(splitPath)-1]

	fileBytes, err := ioutil.ReadAll(inputFile)
	if err != nil {
		log.Fatalf("unable to read file %s: %s", inputFile.Name(), err)
	}

	var asn1Data []byte
	switch inform {
	case "pem":
		p, _ := pem.Decode(fileBytes)
		if p == nil || p.Type != "CERTIFICATE" {
			//log.Fatal("unable to parse PEM")
			return false
		}
		asn1Data = p.Bytes
	case "der":
		asn1Data = fileBytes
	case "base64":
		asn1Data, err = base64.StdEncoding.DecodeString(string(fileBytes))
		if err != nil {
			log.Fatalf("unable to parse base64: %s", err)
		}
	default:
		log.Fatalf("unknown input format %s", format)
	}

	c, err := x509.ParseCertificate(asn1Data)
	if err != nil {
		fmt.Printf("Skip %s\n", inputFile.Name())
		return true
		//log.Fatalf("unable to parse certificate: %s", err)
	} else {
		insertCertificate(certID, c)
		resultSet := zlint.LintCertificate(c)
		insertResults(certID, resultSet)
		return false
	}
}

func printResultsToConsole(zlintResult *zlint.ResultSet) {
	jsonBytes, err := json.Marshal(zlintResult.Results)
	if err != nil {
		log.Fatalf("unable to encode lints JSON: %s", err)
	}
	if prettyprint {
		var out bytes.Buffer
		if err := json.Indent(&out, jsonBytes, "", " "); err != nil {
			log.Fatalf("can't format output: %s", err)
		}
		os.Stdout.Write(out.Bytes())
	} else {
		os.Stdout.Write(jsonBytes)
	}
	os.Stdout.Write([]byte{'\n'})
	os.Stdout.Sync()
}

func processCertificates(pathToCertificates string, inform string) {
	files, err := ioutil.ReadDir(pathToCertificates)
	if err != nil {
		log.Fatal(err)

	}
	var counter = 0
	for _, filePath := range files {
		var inputFile *os.File
		var err error
		inputFile, err = os.Open(pathToCertificates + filePath.Name())
		if err != nil {
			log.Fatalf("unable to open file %s: %s", filePath, err)
		}
		var cert_fmt = inform
		switch {
		case strings.HasSuffix(filePath.Name(), ".der"):
			cert_fmt = "der"
		case strings.HasSuffix(filePath.Name(), ".pem"):
			cert_fmt = "pem"
		}
		isDir, err := isDirectory(inputFile.Name())
		if err != nil {
			log.Fatalf("Could't tell if this was a directory%s: %s", filePath, err)
		}
		if isDir {
			processCertificates(inputFile.Name()+"/", inform)
		} else {
			lint(inputFile, cert_fmt)
			counter++
			if counter%1000 == 0 {
				fmt.Println(counter)
			}
		}
		inputFile.Close()
	}
}

func isDirectory(path string) (bool, error) {
	fileInfo, err := os.Stat(path)
	if err != nil {
		return false, err
	}

	return fileInfo.IsDir(), err
}

func insertCertificate(certID string, certificate *x509.Certificate) {

	var organizationName string
	if len(certificate.Issuer.Organization) != 0 {
		organizationName = certificate.Issuer.Organization[0]
	}

	var subjectOrganizationName string
	if len(certificate.Subject.Organization) != 0 {
		subjectOrganizationName = certificate.Subject.Organization[0]
	}
	stmt, err := db.Prepare("INSERT INTO Certificates(certificate_id, certificate_issuer, certificate_subject, certificate_date) VALUES(?, ?, ?, ?)")
	//stmt, err := db.Prepare("INSERT INTO Certificates(certificate_id, certificate_subject, certificate_date) VALUES(?, ?, ?)")
	checkDatabaseError(err, certID, "certId")
	_, err = stmt.Exec(certID, organizationName, subjectOrganizationName, certificate.NotBefore)
	checkDatabaseError(err, certID, "certId")

	fmt.Printf("Adding certificate: %s\n", certID)
}

func insertLints() {

	var sourceMap = map[lints.LintSource]string{
		0: "UnknownLintSource",
		1: "CABFBaselineRequirements",
		2: "MinimumRequirementsForCodeSigningCertificates",
		3: "RFC5280",
		4: "RFC5891",
		5: "ZLint",
		6: "AWSLabs",
	}

	for _, lint := range lints.Lints {
		stmt, err := db.Prepare("INSERT OR IGNORE INTO lints(lint_name, lint_source, lint_effective_date) VALUES(?,?,?)")
		checkDatabaseError(err, lint.Name, "lintName")
		_, err = stmt.Exec(lint.Name, sourceMap[lint.Source], lint.EffectiveDate)
		checkDatabaseError(err, lint.Name, "lintName")
	}
}

func insertResults(certID string, resultSet *zlint.ResultSet) {

	for lint, result := range resultSet.Results {
		//fmt.Println(lint,result)
		//stmt, err := db.Prepare("INSERT INTO results(Certificate_ID, lint_name, result) VALUES(?,?,?)") //Original
		//Change this back
		stmt, err := db.Prepare("INSERT INTO results(Certificate_id, lint_name, result) VALUES(?,?,?)") //For reading from Database
		//fmt.Println(stmt)
		checkDatabaseError(err, certID, "certId")
		_, err = stmt.Exec(certID, lint, result.Status.String())
		checkDatabaseError(err, certID, "certId")
	}
}

func checkDatabaseError(err error, identifier string, entityType string) {
	if err != nil {
		fmt.Println("Operation failed " + identifier + " " + entityType)
		fmt.Println(err)
	}
}
