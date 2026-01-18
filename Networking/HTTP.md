---
tags:
  - NBBC
  - Networking
---
## **HTTP**
HTTP is a plain-text protocol used for communicating with a web server and retrieving information, this information could be things such as HTML pages, CSS, JavaScript, images etc.
- Developed by Tim Berners-Lee and his team between 1989-1991
![[HTTP-img-202510091530.png]]
## Headers
It's possible to make a request to a web server with just one line **GET / HTTP/1.1**.
But for a much richer web experience, you’ll need to send other data as well. This other data is sent in what is called headers, where headers contain extra information to give to the web server you’re communicating with.
**Request Header**
- Request Method
- The URI and the path-to-resource field: This represents the path portion of the requested URL.
- The request version-number field: This specifies the version of HTTP used by the client.
- Host: Some web servers host multiple websites so by providing the host headers you can tell it which one you require, otherwise you'll just receive the default website for the server.
- The user agent: This is your browser software and version number, telling the web server your browser software helps it format the website properly for your browser and also some elements of HTML, JavaScript and CSS are only available in certain browsers.
- Content-Length: When sending data to a web server such as in a form, the content length tells the web server how much data to expect in the web request. This way the server can ensure it isn't missing any data.
- Accept-Encoding: Tells the web server what types of compression methods the browser supports so the data can be made smaller for transmitting over the internet.
- Cookie: Data sent to the server to help remember your information (see cookies task for more information).
- Several other fields: accept, accept-language, accept encoding, and other fields also appear.
- HTTP requests always end with a blank line to inform the web server that the request has finished.
**Response Header**
- Version of the HTTP protocol the server is using and then followed by the HTTP Status Code.
- Server: This tells us the web server software and version number.
- Date: The current date, time and timezone of the web server.
- Content-Type: tells the client what sort of information is going to be sent, such as HTML, images, videos, pdf, XML.
- Content-Length: tells the client how long the response is, this way we can confirm no data is missing.
- Content-Encoding: What method has been used to compress the data to make it smaller when sending it over the internet.
- Set-Cookie: Information to store which gets sent back to the web server on each request (see cookies task for more information).
- Cache-Control: How long to store the content of the response in the browser's cache before it requests it again.
## Request Methods
- **GET:** Retrieves information from the server  
- **HEAD:** Basically the same as **GET** but returns only HTTP headers and no document body  
- **POST:** Sends data to the server (typically using HTML forms, API requests, and so on)  
- **TRACE:** Does a message loopback test along the path to the target resource  
- **PUT:** Uploads a representation of the specified URI  . This method is used to update content on a server.
- **DELETE:** Deletes the specified resource  
- **OPTIONS:** Returns the HTTP methods that the server supports  
- **CONNECT:** Converts the request connection to a transparent TCP/IP tunnel.
## HTTP URL Structure
URL : Uniform Resource Locator
- **Scheme:** This is the portion of the URL that designates the underlying protocol to be used (for example, HTTP, FTP); it is followed by a colon and two forward slashes ( **//** ). 
- **User:** Some services require authentication to log in, you can put a username and password into the URL to log in.
- **Host:** This is the IP address (numeric or DNS-based) for the web server being accessed; it usually follows the colon and two forward slashes. 
- **Port:** This optional portion of the URL designates the port number to which the target web server listens. (The default port number for HTTP servers is 80, but some configurations are set up to use an alternate port number.) 
- **Path:** This is the path from the “root” directory of the server to the desired resource. In this case, you can see that there is a directory called **dir**. (Keep in mind that, in reality, web servers may use aliasing to point to documents, gateways, and services that are not explicitly accessible from the server’s root directory.)
- **Path-segment-params:** This is the portion of the URL that includes optional name/value pairs (that is, path segment parameters). A path segment parameter is typically preceded by a semicolon (depending on the programming language used), and it comes immediately after the path information. Path segment parameters are not commonly used. In addition, it is worth mentioning that these parameters are different from query-string parameters (often referred to as _URL parameters_ ).
- **Query-string:** This optional portion of the URL contains name/value pairs that represent dynamic parameters associated with the request. These parameters are commonly included in links for tracking and context-setting purposes. They may also be produced from variables in HTML forms. Typically, the query string is preceded by a question mark. Equals signs (=) separate names and values, and ampersands ( **_&_** ) mark the boundaries between name/value pairs.
- **Fragment:** This is a reference to a location on the actual page requested. This is commonly used for pages with long content and can have a certain part of the page directly linked to it, so it is viewable to the user as soon as they access the page. (eg: example.com/#heading1)
## Web Server Response Codes
When a web server responds to a request it sends a 3 digit status code which lets the client know the result of the request. 
#### 1xx: Information
| Message:                | Description:                                                                                                      |
| ----------------------- | ----------------------------------------------------------------------------------------------------------------- |
| 100 Continue            | The server has received the request headers, and the client should proceed to send the request body               |
| 101 Switching Protocols | The requester has asked the server to switch protocols                                                            |
| 103 Early Hints         | Used with the Link header to allow the browser to start preloading resources while the server prepares a response |
#### 2xx: Successful
| Message:                          | Description:                                                                                                                           |
| --------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------- |
| 200 OK                            | The request is OK (this is the standard response for successful HTTP requests)                                                         |
| 201 Created                       | The request has been fulfilled, and a new resource is created                                                                          |
| 202 Accepted                      | The request has been accepted for processing, but the processing has not been completed                                                |
| 203 Non-Authoritative Information | The request has been successfully processed, but is returning information that may be from another source                              |
| 204 No Content                    | The request has been successfully processed, but is not returning any content                                                          |
| 205 Reset Content                 | The request has been successfully processed, but is not returning any content, and requires that the requester reset the document view |
| 206 Partial Content               | The server is delivering only part of the resource due to a range header sent by the client                                            |
#### 3xx: Redirection
|Message:|Description:|
|---|---|
|300 Multiple Choices|A link list. The user can select a link and go to that location. Maximum five addresses|
|301 Moved Permanently|The requested page has moved to a new URL|
|302 Found|The requested page has moved temporarily to a new URL|
|303 See Other|The requested page can be found under a different URL|
|304 Not Modified|Indicates the requested page has not been modified since last requested|
|307 Temporary Redirect|The requested page has moved temporarily to a new URL|
|308 Permanent Redirect|The requested page has moved permanently to a new URL|
#### 4xx: Client Error
|Message:|Description:|
|---|---|
|400 Bad Request|The request cannot be fulfilled due to bad syntax|
|401 Unauthorized|The request was a legal request, but the server is refusing to respond to it. For use when authentication is possible but has failed or not yet been provided|
|402 Payment Required|_Reserved for future use_|
|403 Forbidden|The request was a legal request, but the server is refusing to respond to it|
|404 Not Found|The requested page could not be found but may be available again in the future|
|405 Method Not Allowed|A request was made of a page using a request method not supported by that page|
|406 Not Acceptable|The server can only generate a response that is not accepted by the client|
|407 Proxy Authentication Required|The client must first authenticate itself with the proxy|
|408 Request Timeout|The server timed out waiting for the request|
|409 Conflict|The request could not be completed because of a conflict in the request|
|410 Gone|The requested page is no longer available|
|411 Length Required|The "Content-Length" is not defined. The server will not accept the request without it|
|412 Precondition Failed|The precondition given in the request evaluated to false by the server|
|413 Request Too Large|The server will not accept the request, because the request entity is too large|
|414 Request-URI Too Long|The server will not accept the request, because the URI is too long. Occurs when you convert a POST request to a GET request with a long query information|
|415 Unsupported Media Type|The server will not accept the request, because the media type is not supported|
|416 Range Not Satisfiable|The client has asked for a portion of the file, but the server cannot supply that portion|
|417 Expectation Failed|The server cannot meet the requirements of the Expect request-header field|
#### 5xx: Server Error
|Message:|Description:|
|---|---|
|500 Internal Server Error|A generic error message, given when no more specific message is suitable|
|501 Not Implemented|The server either does not recognize the request method, or it lacks the ability to fulfill the request|
|502 Bad Gateway|The server was acting as a gateway or proxy and received an invalid response from the upstream server|
|503 Service Unavailable|The server is currently unavailable (overloaded or down)|
|504 Gateway Timeout|The server was acting as a gateway or proxy and did not receive a timely response from the upstream server|
|505 HTTP Version Not Supported|The server does not support the HTTP protocol version used in the request|
|511 Network Authentication Required|The client needs to authenticate to gain network access|
- https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Status
## Cookies
 Cookies are small piece of data that is stored on your computer. 
 - Cookies are saved when you receive a "Set-Cookie" header from a web server. Then every further request you make, you'll send the cookie data back to the web server. 
- Cookies can be used for many purposes but are most commonly used for website authentication. The cookie value won't usually be a clear-text string where you can see the password, but a token (unique secret code that isn't easily humanly guessable).
- 

>A REST API (or **_RESTful API_**) is a type of application programming interface (API) that conforms to the specification of the representational state transfer (REST) architectural style and allows for interaction with web services. REST APIs are used to build and integrate multiple-application software. In short, if you want to interact with a web service to retrieve information or add, delete, or modify data, an API helps you communicate with such a system in order to fulfill the request. REST APIs use JSON as the standard format for output and requests.


---
- [HTTP specs](https://httpwg.org/specs/)
- 