The `Content-Type` HTTP header is used to indicate the media type (MIME type) of the resource being sent from the server to the client (browser). It tells the browser how to interpret and render the content of the response.

1. **Content Interpretation**: The `Content-Type` header informs the browser about the type of data being sent. This helps the browser decide how to handle the content. For example:

   - `text/html`: The content is HTML and should be rendered as a web page.
   - `application/json`: The content is JSON, which should be parsed as a JavaScript object.
   - `application/javascript`: The content is JavaScript code that should be executed.

2. **Handling User Inputs**: For forms that upload files, the `Content-Type` is used to specify the type of file being uploaded to ensure proper processing on the server.

3. **Security and Validation**: Many web applications use the `Content-Type` header to validate incoming requests to protect against attacks such as XML External Entity (XXE) attacks or Cross-Site Scripting (XSS).
## Example

When a browser makes a request to a server for a web page, the server responds with the following:

```
HTTP/1.1 200 OK

Content-Type: text/html
```

In this example, the `Content-Type: text/html` header indicates that the content being returned is an HTML document, so the browser will render it accordingly.

## X-Content-Type-Options

The `X-Content-Type-Options` HTTP header is a security feature used by web servers to instruct browsers on how to handle content types. It is present in the **response** sent from the server to the client (browser). 

When the header is set to `nosniff`, it tells the browser to **not perform MIME type sniffing** and to strictly adhere to the `Content-Type` specified by the server. This prevents the browser from interpreting content based on its actual contents rather than the declared type.

## Example of MIME Type Sniffing

**Scenario: Improper MIME Type Configuration**

1. **Server Configuration**: The server is misconfigured to serve a JavaScript file with the wrong MIME type.

   - **Header Sent by the Server**:

```
Content-Type: text/plain
```

2. **Actual Content of the File**:

```
 <script>alert('XSS');</script>
```

3. **Browser Behavior**:

   - The browser receives the response and sees the `Content-Type` as `text/plain`.

   - Due to MIME type sniffing, the browser inspects the content and recognizes the `<script>` tag.

   - It may then execute the script, treating the content as HTML or JavaScript.
  
  ---

- [Content types](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Type)
