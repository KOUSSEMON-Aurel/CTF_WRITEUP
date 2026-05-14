# ORDER ORDER - PicoCTF Challenge (300 points)

## Challenge Overview
- **Type**: SQL Injection via ORDER BY clause
- **Site**: http://crystal-peak.picoctf.net:53782/
- **Description**: An Expense Tracker app with SQL injection vulnerability in sorting

## Hint
"What does order in SQL Injection mean?" - This refers to the `ORDER BY` clause.

## Key Concept: ORDER BY Injection
ORDER BY is vulnerable because:
1. It's often used for sorting without proper sanitization
2. Can be used to determine column counts
3. Can be exploited for blind SQL injection
4. Can cause error-based SQL injection

## Exploitation Techniques

### 1. Detect Vulnerable Parameter
The vulnerability is likely in:
- A sort parameter (e.g., `?sort=field`)
- An order parameter (e.g., `?order=ASC`)
- Try typical parameters: `sort`, `order_by`, `order`, `by`

### 2. Test for Injection
Basic tests:
```
order=column - check if it's reflected
order=column, (SELECT COUNT(*) FROM information_schema.tables) - test injection
order=1 - numeric injection
order=1 AND 1=1 - conditional injection
```

### 3. Extract Data Using UNION-Based or Blind SQL Injection
Once injection is confirmed, extract:
- Database name
- Table names
- Column names
- Sensitive data (hopefully the flag)

## Progress
- [ ] Identify vulnerable parameter
- [ ] Confirm injection point
- [ ] Extract database structure
- [ ] Get the flag
