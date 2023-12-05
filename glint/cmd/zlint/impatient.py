import sqlite3
db = sqlite3.connect("lint_results.db")
result = db.execute("select count(*) from  certificates")
print(result.fetchall())
