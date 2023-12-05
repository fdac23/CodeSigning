import sqlite3
import json
import sys

def setup():
    resultsDB= "lint_results.db"
    if (len(sys.argv)) == 2:
            resultsDB = sys.argv[1]
    print(resultsDB)

    db = sqlite3.connect(resultsDB)
    lints = getAllLints(db)
    cas = getAllCAs(db)
    return db, lints, cas


def getAllCerts(db):
    certsWithErrors = []
    certsWithoutErrors = []
    listOfCerts = db.execute("SELECT certificate_id FROM certificates")
    for cert in listOfCerts.fetchall():
        query = "Select count(*) From results where certificate_id = '"+cert[0]+"' AND result = 'error'"
        errors = db.execute(query)
        if(errors.fetchall()[0][0] > 0 ):
            certsWithErrors.append(cert[0])
        else:
            certsWithoutErrors.append(cert[0])
    #print("Certs With Errors:", len(certsWithErrors))
    #print("Certs Without Errors:", len(certsWithoutErrors))
    return certsWithErrors,certsWithoutErrors
def getAllCAs(db):
    ca_Dict = {}
    ca_list = [row[0] for row in db.execute("SELECT DISTINCT certificate_issuer FROM certificates")]
    for ca in ca_list:
        ca_Dict.update({ca:0})
    #print(ca_Dict)
    return ca_Dict

def getAllLints(db):
    lint_Dict = {}
    lint_list = [row[0] for row in db.execute("SELECT DISTINCT lint_name FROM lints")]
    for lint in lint_list:
        lint_Dict.update({lint:0})
    #print(ca_Dict)
    return lint_Dict

def getErrors(db, cert, lints):
    query = "Select lint_name From results where certificate_id = '"+cert+"' AND result = 'error'"
    errors = db.execute(query)
    for error in errors.fetchall():
        lints.update({error[0]:(lints.get(error[0])+1)})

def reportCA(db, cert, cas):
    query = "Select certificate_issuer From certificates where certificate_id = '"+cert+"'"
    ca = db.execute(query).fetchall()[0]
    cas.update({ca[0]:(cas.get(ca[0])+1)})

def originalAnalysisFunction(db,cas,lints):
    dates = ["2016-01", "2016-02", "2016-03", "2016-04", "2016-05", "2016-06",
         "2016-07", "2016-08", "2016-09", "2016-10", "2016-11", "2016-12",
         "2017-01", "2017-02", "2017-03", "2017-04", "2017-05", "2017-06",
         "2017-07", "2017-08", "2017-09", "2017-10", "2017-11", "2017-12",
         "2018-01", "2018-02", "2018-03", "2018-04", "2018-05", "2018-06",
         "2018-07", "2018-08", "2018-09", "2018-10", "2018-11", "2018-12",
         "2019-01", "2019-02", "2019-03", "2019-04", "2019-05", "2019-06",
         "2019-07", "2019-08", "2019-09", "2019-10", "2019-11", "2019-12",
         "2020-01", "2020-02", "2020-03", "2020-04", "2020-05", "2020-06",
         "2020-07", "2020-08", "2020-09", "2020-10", "2020-11", "2020-12",
         "2021-01", "2021-02", "2021-03", "2021-04", "2021-05", "2021-06",
         "2021-07", "2021-08", "2021-09", "2021-10", "2021-11", "2021-12",
         "2022-1"]

    all_results = {}
    for ca in cas.keys():
        all_results.update({ca: {}})
        for lint in lints:
            all_results[ca].update({lint: {}})

    for date in dates:
    #print("Collecting data for: ", date)
        for ca in cas.keys():
            for lint in lints.keys():            
                    certificates_issued_by_ca = [row for row in db.execute(
                    "SELECT certificate_id, lint_name, certificate_date, result "
                    "FROM certificates NATURAL JOIN results "
                    "WHERE date(certificate_date,'start of month') = ? AND certificate_issuer= ? AND lint_name = '"+lint+"'", (date+"-01", ca,))]
                    result_list = list(map(lambda item: item[3], certificates_issued_by_ca))
                    #if(len(result_list)>0):
                        #print(certificates_issued_by_ca)
                        #print(result_list)
                    total = len(result_list)
                    _error = len(list(filter(lambda item: item == 'error', result_list)))
                    _pass = len(list(filter(lambda item: item == 'pass', result_list)))
                    _info = len(list(filter(lambda item: item == 'info', result_list)))
                    _warn = len(list(filter(lambda item: item == 'warn', result_list)))
                    _NA = len(list(filter(lambda item: item == 'NA', result_list)))
                    _NE = len(list(filter(lambda item: item == 'NE', result_list)))

                    if total != 0:
                        success_rate = (_pass + _NA + _NE)/total
                        all_results[ca][lint].update({date: success_rate})
                    else:
                        success_rate = 1.0
    #print(all_results)
    with open("./VXUnderground.json", "w") as file:
        json.dump(all_results, file, indent=4)
    print("Done")


def main():
    db, lints, cas = setup()
    '''
    certsWithErrors, certsWithoutErrors = getAllCerts(db)
    for cert in certsWithErrors:
        getErrors(db,cert,lints)
        reportCA(db,cert,cas)
    for lint in lints.items():
        print(lint)
    for ca in cas.items():
        print(ca)
    '''
    originalAnalysisFunction(db,cas,lints)
main()

