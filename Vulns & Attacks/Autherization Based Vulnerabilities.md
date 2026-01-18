---
tags:
  - CyberSec
  - CiscoEH
---
Authorization concerns the actions that users are permitted to do. While users might successfully authenticate to a system with their username and password, they may not be allowed to access certain resources, change or delete data, or change system settings. Only users with appropriate authorization are allowed to do these things.
## Parameter Pollution
HTTP parameter pollution (HPP) vulnerabilities can be introduced if multiple HTTP parameters have the same name. This issue may cause an application to interpret values incorrectly. An attacker may take advantage of HPP vulnerabilities to bypass input validation, trigger application errors, or modify internal variable values.
    >**NOTE** HPP vulnerabilities can lead to server- and client-side attacks.
An attacker can find HPP vulnerabilities by finding forms or actions that allow user-supplied input. Then the attacker can append the same parameter to the **GET** or **POST** data – but with a different value assigned.
```
Consider the following URL:
https://store.h4cker.org/?search=cars
This URL has the query string **search** and the parameter value **cars**. The parameter might be hidden among several other parameters. An attacker could leave the current parameter in place and append a duplicate, as shown here:
https://store.h4cker.org/?search=cars&results=20
The attacker could then append the same parameter with a different value and submit the new request:
https://store.h4cker.org/?search=cars&results=20&search=bikes
After submitting the request, the attacker could analyze the response page to identify whether any of the values entered were parsed by the application. Sometimes it is necessary to send three HTTP requests for each HTTP parameter. If the response from the third parameter is different from the first one – and the response from the third parameter is also different from the second one – this may be an indicator of an impedance mismatch that could be abused to trigger HPP vulnerabilities.
```

## ![[IDOR - Insecure direct object reference|Insecure Direct Object Reference]]

