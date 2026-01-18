### What is a **callback** in JSONP?

**JSONP (JSON with Padding)** is a technique used to overcome the same-origin policy in web browsers. It allows a web page to request data from a server in a different domain, which is usually restricted by the Same-Origin Policy.

The core idea of JSONP is this:

- The client includes a `<script>` tag with a `src` pointing to a remote server.
    
- The server responds with **JavaScript code** (not raw JSON), which **invokes a function (callback)** with the data as an argument.
    

#### Example:

```html
<script src="https://example.com/data?callback=handleData"></script>
```

If the server responds with:

```js
handleData({ "name": "John", "age": 30 });
```

Then the browser will execute it, calling the `handleData` function defined on the page.

---

### What is the `callback` parameter?

The `callback` is a **query parameter** in the request that tells the server which JavaScript function to wrap the data in. It's often user-controlled.

So this:

```
https://example.com/data?callback=handleData
```

can return:

```js
handleData({ "data": "value" });
```

---

### How is JSONP used in **XSS / CSP Bypass**?

#### 1. **XSS via JSONP**

If a site includes a JSONP endpoint and **does not validate or sanitize the `callback` parameter**, an attacker can inject arbitrary JavaScript.

**Example**:

```html
<script src="https://vulnerable.com/jsonp?callback=alert(1)"></script>
```

If the response is:

```js
alert(1)({ "key": "value" });
```

JavaScript sees this as a syntax error, but with some trickery (e.g., if the server responds with just `alert(1)`, or something like `*/alert(1)//`), the attacker might get execution.

A more realistic payload could be:

```html
<script src="https://vulnerable.com/jsonp?callback=evil"></script>
<script>
  function evil(data) {
    // exploit here
    alert("XSS via JSONP");
  }
</script>
```

---

#### 2. **CSP Bypass using JSONP**

Content Security Policy (CSP) helps mitigate XSS by restricting sources of scripts, but if a CSP allows loading scripts from a JSONP-enabled domain, attackers can exploit that.

**Example scenario**:

- CSP allows `script-src https://api.trusted.com`.
    
- `https://api.trusted.com/jsonp?callback=anything` returns arbitrary JavaScript (unsanitized).
    
- Attacker injects:
    

```html
<script src="https://api.trusted.com/jsonp?callback=alert(1)"></script>
```

Since `https://api.trusted.com` is allowed by CSP, the browser loads and executes the response — **CSP is bypassed**.

#### Realistic Attack Flow:

1. Attacker finds a JSONP endpoint on a trusted domain in the CSP.
    
2. Attacker injects a `<script>` tag pointing to that JSONP endpoint with a malicious `callback`.
    
3. The browser loads and executes the JavaScript — **bypassing CSP and achieving XSS**.
    

---
