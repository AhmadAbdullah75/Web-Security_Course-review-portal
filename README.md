A simple student course-review portal: users log in, search courses, post reviews,
and update their profile/email. Chosen because it naturally needs a login form,
a search field, user-generated content (reviews), and a state-changing action
(email update) — covering every required vulnerability class.

## Tech stack
- Node.js + Express
- EJS templates
- SQLite3 (file-based DB, no separate DB server needed)
- express-session for login sessions
- csurf (safe version only) for CSRF tokens

## Folder structure

vulnerable/ -> deliberately insecure version (port 3000)
safe/ -> hardened version, same features (port 3001)
seed-data.sql -> reference schema + seed rows
csrf-attack.html -> standalone page used to demonstrate the CSRF attack


## How to run

### Vulnerable version

cd vulnerable
npm install
node server.js

Open http://localhost:3000

### Safe version

cd safe
npm install
node server.js

Open http://localhost:3001

Both can run at the same time (different ports, different DB files).

## Default login credentials (seeded in the database)
| Username | Password |
|---|---|
| admin | admin123 |

## How to test each vulnerability

1. **Reflected XSS** — visit `http://localhost:3000/search?q=<script>alert('reflected')</script>` → popup fires. Same URL on port 3001 → shows as plain text, no popup.
2. **Stored XSS** — log in, go to `/course/CS101`, submit a review containing `<script>alert('stored')</script>` → popup fires every time the page is viewed. Same action on the safe version shows the comment as plain text.
3. **DOM XSS** — log in, visit `/profile#<img src=x onerror=alert('dom')>` → popup fires. Safe version shows the raw text instead.
4. **CSRF** — log in to the vulnerable app, then open `csrf-attack.html` in the same browser → email changes without consent. Point the same file at the safe app (port 3001) → request is blocked with a 403 "invalid CSRF token" response.
5. **SQL Injection (easy)** — on `/login`, enter `admin' OR '1'='1' --` as the username (any password) → logs in without knowing the real password. Fails on the safe version.
6. **SQL Injection (intermediate)** — `/check-user?username=admin' AND '1'='1` returns "exists"; `...AND '1'='2` returns "not found" — used to infer data blindly. Both return "not found" on the safe version.
7. **SQL Injection (advanced)** — on `/search?q=`, chain payloads: `x' ORDER BY 1--` (find column count) → `x' UNION SELECT name,name FROM sqlite_master WHERE type='table'--` (list tables) → `x' UNION SELECT sql,sql FROM sqlite_master WHERE name='users'--` (list columns) → `x' UNION SELECT username,password FROM users--` (dump credentials). All fail on the safe version.


