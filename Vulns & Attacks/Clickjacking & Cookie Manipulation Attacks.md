---
tags:
  - CyberSec
  - CiscoEH
  - Vulns/Web
---
# Clickjacking
_Clickjacking_ involves using multiple transparent or opaque layers to induce a user into clicking on a web button or link on a page that he or she was not intended to navigate or click. Clickjacking attacks are often referred to as _UI redress attacks_. User keystrokes can also be hijacked using clickjacking techniques. An attacker can launch a clickjacking attack by using a combination of CSS stylesheets, iframes, and text boxes to fool the user into entering information or clicking on links in an invisible frame that can be rendered from a site the attacker created.

According to OWASP, these are the two most common techniques for preventing and mitigating clickjacking:
- Send directive response headers to the proper content security policy ([[CSP - Content Security Policy|CSP]]) frame ancestors to instruct the browser not to allow framing from other domains. (This replaces the older X-Frame-Options HTTP headers.)
- Use defensive code in the application to make sure the current frame is the top-level window.

The OWASP Clickjacking Defense Cheat Sheet provides additional details about how to defend against clickjacking attacks. The cheat sheet can be accessed at [_https://www.owasp.org/index.php/Clickjacking_Defense_Cheat_Sheet_](https://www.owasp.org/index.php/Clickjacking_Defense_Cheat_Sheet).

# Cookie Manipulation Attacks
_Cookie manipulation attacks_ are often referred to as _stored DOM-based attacks_ (or _vulnerabilities_ ). Cookie manipulation is possible when vulnerable applications store user input and then embed that input in a response within a part of the DOM. This input is later processed in an unsafe manner by a client-side script. An attacker can use a JavaScript string (or other scripts) to trigger the DOM-based vulnerability. Such scripts can write controllable data into the value of a cookie.

An attacker can take advantage of stored DOM-based vulnerabilities to create a URL that sets an arbitrary value in a user’s cookie.

**NOTE** The impact of a stored DOM-based vulnerability depends on the role that the cookie plays within the application.

**TIP** A best practice for avoiding cookie manipulation attacks is to avoid dynamically writing to cookies using data originating from untrusted sources.