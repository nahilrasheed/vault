---
tags:
  - CyberSec
  - CiscoEH
---
# XML External Entity (XXE)
XML external entity injection (also known as XXE) is a web security vulnerability that allows an attacker to interfere with an application's processing of XML data. It often allows an attacker to view files on the application server filesystem, and to interact with any back-end or external systems that the application itself can access.

## XML
XML structures data by using tags, and provides a rigid schema mechanism that describes the nesting, presence, and type of tags. For example, XML is used in communicating data between client and server, or to locally serialize and store data.

The XML standard has a concept called an “entity”, which represents a unit of data and there are many different types of entities in the XML specification. There is a type of custom entity called an “XML External Entity" denoted by the use of the `SYSTEM` keyword. The entity specifies a URL where the entity is defined, using either HTTP or file protocols. External entities can be used to retrieve both remote and local files.

XML external entity injection (XXE) is an attack where untrusted data is provided to a misconfigured XML parser.
If an XML parser is configured to allow external entities, attackers can take advantage of this to access internal resources, including the server’s file system and other connected systems.

## In Action
Assume a POST request that receives data in XML
```xml
POST /profile/name 

<?xml version="1.0" ?>
<Profile >
	<name>Bob</name>
</Profile>
```

We can inject a payload like
```http
POST /profile/name 

<?xml version="1.0" ?>
<!DOCTYPE foo [
  <!ENTITY topping2 SYSTEM "file:///etc/passwd">]>
<Profile >
  <name>Bob</name>
</Profile>
```
This may give a response containing the content of `/etc/passwd`
In the example above, the  web application trusted the XML input we provided when we intercepted and edited the `POST` request. By injecting our custom external entity, the XML parser processed the entity and retrieved the contents of the `/etc/passwd` file, and then displayed the contents of the file along with the user’s name. This was possible because the XML parser that the web application uses has not disabled the use of external entities.
The vulnerable piece of code in our JavaScript app looks like:
```js
const app = require("express")(),
const libxml = require("libxmljs");
app.post("/profile/name", (req, res) => {
  favorite = libxml.parseXml(req.body, { noent: true });
  editname(name)
});
```
The web application uses the `libxml` library as its parser library, as NodeJS doesn’t provide a native XML parser. The issue in this code is calling the XML parser with the `noent:true` option which allows for external entities.
The code above uses the built in `SimpleXMLElement` class, which resolves entities by default.

## XXE mitigation
The safest way to mitigate XXE attacks in most frameworks is by disabling document type definitions completely. This will remove the ability to create custom entities. If this isn’t an option for your application, you’ll need to disable external entities and external document type declarations, depending on the parser in use.
In our situation, the parser `libxmljs` actually disables external entities by default! The `noent:true` option included when parsing the XML actually enabled it. So all we need to do is remove it!
