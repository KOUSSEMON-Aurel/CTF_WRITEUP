# Onlineticket - Race Condition Writeup

## Information

- **URL**: <http://onlineticket.hv>
- **IP**: 172.20.22.197
- **Vulnerability**: Race Condition (Time-of-Check to Time-of-Use - TOCTOU)

## Objective

Purchase a ticket by repeatedly applying a single-use discount code (`CODE50`) to lower the total price to 0$.

## Steps

1. **Reconnaissance**
    - Accessed `http://onlineticket.hv`.
    - Found a ticket price of 300$, but initial account balance was 130$.
    - A discount code (`CODE50`) provided a 50$ discount but could only be used once.

2. **Vulnerability Analysis**
    - The server likely checks if the discount code was already used before applying the discount ("Time-of-Check").
    - If multiple requests apply the discount simultaneously, they might all pass the check before the server updates the database ("Time-of-Use").
    - This creates a race condition window where multiple discounts can be applied.

3. **Exploitation**
    - Reset the cart and balance using `http://onlineticket.hv/reset.php`.
    - Crafted a Python script (or shell loop) to send concurrent POST requests applying the `CODE50` discount.

    ```bash
    for _ in {1..30}; do curl -b cookies.txt -d "code=CODE50&useDiscountCode=" http://onlineticket.hv & done; wait
    ```

    - The server failed to lock the transaction properly, resulting in multiple discounts being applied.
    - The total price dropped to 0$.

4. **Transaction Completion**
    - After successfully reducing the price to 0$, proceeded to checkout:

    ```bash
    curl -b cookies.txt -d "buy=Buy Ticket" http://onlineticket.hv
    ```

    - The purchase was successful without spending any "real" money.

## Result

The order number received after purchasing the ticket is: **z8fc67da1009a64d78**
