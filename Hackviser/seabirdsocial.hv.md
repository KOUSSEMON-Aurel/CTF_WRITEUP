# Seabirdsocial - CSRF Writeup

## Information

- **URL**: <http://seabirdsocial.hv>
- **IP**: 172.20.27.161
- **Vulnerability**: Cross-Site Request Forgery (CSRF)

## Objective

Exploit a CSRF vulnerability to make the user "alex" follow your account ("user") and reveal confidential information.

## Steps

1. **Reconnaissance**
    - Accessed `http://seabirdsocial.hv`.
    - Found a "Follow" button for other users (`/index.php?follow=sarah`).
    - The follow action is initiated by a simple GET request. There is no anti-CSRF token or confirmation.

2. **Vulnerability Analysis**
    - The lack of anti-CSRF tokens means an attacker can trick another user into performing an action (like following) if they visit a malicious link while authenticated.
    - The "alex" user is active and can receive messages at `/messages.php`. We can send a DM containing a link.

3. **Exploitation**
    - Crafted a link that triggers the follow action on my account ("user"): `http://seabirdsocial.hv/index.php?follow=user`.
    - Sent this link as a direct message to "alex".

    ```bash
    curl -X POST -d "send_dm_to=alex&dm_body=http://seabirdsocial.hv/index.php?follow=user" http://seabirdsocial.hv/messages.php?with=alex
    ```

4. **Data Extraction**
    - The "alex" bot likely clicked the link automatically upon receiving the message.
    - The follow action was performed successfully.
    - Refreshed the page and a success banner appeared with the secret keyword.

## Result

The confidential information revealed is: **Sunflowers**
