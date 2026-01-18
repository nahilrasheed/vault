CSP (Content Security Policy) is a security standard that adds an extra layer of protection against cross-site scripting (XSS), clickjacking, and other code injection attacks. It works by allowing you to define a whitelist of sources that the browser is allowed to load resources from.
CSP is implemented by sending a specific HTTP header from the web server.
- Including the `Content-Security-Policy` header
- <meta> element in the DOM

eg: 
Header: `Content-Security-Policy: default-src 'self'; script-src 'self' ; img-src 'self' https://example.com;` 
```html
<meta
http-equiv="Content-Security-Policy"
content="default-src ‘self’; img-src https://www.site.com;" />
```
### Directives
CSP policies are built using directives that define the allowed sources for different types of resources.
Common CSP directives include:
- `default-src`: Serves as a fallback for other directives when they are not explicitly specified.
- `script-src`: Defines the allowed sources for JavaScript code.
- `style-src`: Defines the allowed sources for CSS stylesheets.
- `img-src`: Defines the allowed sources for images.
- `connect-src`: Defines the allowed sources for making HTTP requests (e.g., via `fetch`, `XMLHttpRequest`, or WebSockets).
- `font-src`: Defines the allowed sources for fonts.
- `media-src`: Defines the allowed sources for media files (audio and video).
- `object-src`: Defines the allowed sources for plugins like Flash.
- `frame-src`: Defines the allowed sources for frames and iframes.
- `base-uri`: Defines the allowed URLs that can be used in a `<base>` element.
- `form-action`: Defines the allowed URLs that can be used as the target of a form submission.
- `report-uri`: Specifies a URL to which the browser should send violation reports when a policy is broken.
- `sandbox`: Specifies restrictions for the resources being applied
### Values
- `none` : Prevents loading content from any source.
- `self` : Allows loading content from the same origin (excluding subdomains).
- `unsafe-inline` : Allows the use of inline scripts and styles.
- `unsafe-eval` : Allows the use of “eval()" functions.
- `<scheme>` : Allows loading content over a specific scheme (e.g., “https:’).
- `<host-source>` : Allows loading content from a specific host or domain.
- `data:` : Allows the use of inline data such as base64-encoded images. 
- `blob:` : Allows the use of Blob URIs.

- CSP can also be configured in "report-only" mode, which allows you to monitor the effects of a policy without enforcing it. This is done using the `Content-Security-Policy-Report-Only` header.