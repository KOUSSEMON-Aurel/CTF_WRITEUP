# Northstarstudio - SSRF Writeup

## Information

- **URL**: <http://northstarstudio.hv>
- **IP**: 172.20.29.13
- **Vulnerability**: Server-Side Request Forgery (SSRF)

## Objective

1. Use SSRF to view the `/etc/passwd` file and find the most recently added user.
2. Use SSRF to access the hidden word on the HTTP service listening on port 9090 on the internal network.

## Steps (Question 9)

1. **Reconnaissance**
    - Analyzed the website `http://northstarstudio.hv`.
    - Found a suspicious request in the HTML source (`index.html`): `proxy.php?url=http://northstarstudio.hv/static/images/hero.jpeg`.
    - This suggests a backend script acting as a proxy.

2. **Vulnerability Analysis**
    - The `proxy.php` script likely takes a URL as input and fetches the content.
    - If input validation is insufficient, we can make it request arbitrary URLs, including internal resources like `file:///` or `http://localhost`.

3. **Exploitation**
    - Crafted a request using `proxy.php` to access local files via the file protocol: `file:///etc/passwd`.

    ```bash
    curl "http://northstarstudio.hv/proxy.php?url=file:///etc/passwd"
    ```

    - The server returned the content of `/etc/passwd`.

4. **Data Extraction**
    - Examined potential user names at the bottom of the `/etc/passwd` file.
    - Found the user `beethoven` with ID 1001.

## Result

The most recently added user to the system is: **beethoven**

## Steps (Question 10)

1. **Reconnaissance**
    - We know there's an internal HTTP service on port 9090.
    - We can use the confirmed SSRF vulnerability to access it.

2. **Exploitation**
    - Crafted a request to access `http://127.0.0.1:9090`.

    ```bash
    curl "http://northstarstudio.hv/proxy.php?url=http://127.0.0.1:9090"
    ```

    - The server successfully fetched the content from the internal service.

3. **Data Extraction**
    - Inspected the HTML response body.
    - Found the hidden word `TheStarryNight` inside an `<h1>` tag.

## Result

The hidden word in the content is: **TheStarryNight**
