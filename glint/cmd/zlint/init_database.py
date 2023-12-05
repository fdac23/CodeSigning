#Creates the database that the results of the linting are stored in
import sqlite3

conn = sqlite3.connect('lint_results.db')
db = conn.cursor()

db.execute('DROP TABLE IF EXISTS results')
db.execute('DROP TABLE IF EXISTS Certificates')
db.execute('DROP TABLE IF EXISTS lints')

db.execute('''CREATE TABLE Certificates(
    certificate_ID text primary key not null, 
    certificate_issuer text,
    certificate_subject text, 
    certificate_date text)''')

db.execute('''CREATE TABLE lints(
    lint_name text primary key not null, 
    lint_source text, 
    lint_effective_date text)''')

db.execute('''CREATE TABLE results(
    Certificate_ID text not null, 
    lint_name text not null, 
    result text,
    primary key (Certificate_ID, lint_name),
    foreign key (Certificate_ID) references Certificates,
    foreign key (lint_name) references lints)''')
