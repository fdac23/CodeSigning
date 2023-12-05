import os
import sys
basePath = '/datasets/waltersquires1/OnlyUniqueCerts/'
if len(sys.argv) < 2 or len(sys.argv) > 2:
	    print("Pass directory name as argument")
else:
	dataset = sys.argv[1]
	os.system('python3 init_database.py')
	datasetPath = basePath+dataset+"/"
	for certType in ["CS","TSA","Self-Signed","Error"]:
		subdirectoryPath = datasetPath + certType + "_" + dataset + "/"
		os.system(' go run main.go ' + subdirectoryPath)
	os.system('mv lint_results.db ' + dataset + "_lint_results.db")
	#os.system('rm lint_results.db ')
print("DONE")
