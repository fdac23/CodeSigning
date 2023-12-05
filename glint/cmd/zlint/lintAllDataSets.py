import os
import sys
basePath = '/datasets/waltersquires1/OnlyUniqueCerts/'
os.system('python3 init_database.py')
for dataset in ["VXUnderground","Sorel","VirusShare","MalCert","ReversingLabs_Malware","ReversingLabs_Benign","NapierOne"]:
    datasetPath = basePath+dataset+"/"
    for certType in ["CS","TSA","Self-Signed","Error"]:
        subdirectoryPath = datasetPath + certType + "_" + dataset + "/"
        os.system(' go run main.go ' + subdirectoryPath)
os.system('mv lint_results.db  AllDatasets_lint_results.db')
        #os.system('rm lint_results.db ')
print("DONE")
