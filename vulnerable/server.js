const express = require('express');
const session = require('express-session');
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');
const path = require('path');

const app = express();
const PORT = 3000;
const db = new sqlite3.Database(path.join(__dirname, 'database.db'));
app.set('view engine', 'ejs');
app.use(express.static(path.join(__dirname, 'public')));
app.use(bodyParser.urlencoded({ extended: true }));

// VULNERABLE: no sameSite/secure cookie flags -> CSRF possible
app.use(session({
  secret: 'vulnerable-secret-key',
  resave: false,
  saveUninitialized: true
}));

// ---------- DB SETUP + SEED ----------
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    password TEXT,
    email TEXT
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS reviews (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    course TEXT,
    author TEXT,
    comment TEXT
  )`);
  db.get(`SELECT COUNT(*) as c FROM users`, (err, row) => {
    if (row && row.c === 0) {
      db.run(`INSERT INTO users (username, password, email) VALUES ('admin','admin123','admin@portal.com')`);
      db.run(`INSERT INTO users (username, password, email) VALUES ('alice','password1','alice@portal.com')`);
    }
  });
  db.get(`SELECT COUNT(*) as c FROM reviews`, (err, row) => {
    if (row && row.c === 0) {
      db.run(`INSERT INTO reviews (course, author, comment) VALUES ('CS101','alice','Great course!')`);
      db.run(`INSERT INTO reviews (course, author, comment) VALUES ('CS102','bob','Could be better.')`);
    }
  });
});

function requireLogin(req, res, next) {
  if (!req.session.userId) return res.redirect('/login');
  next();
}

// ---------- ROOT -> redirect to login ----------
app.get('/', (req, res) => res.redirect('/login'));

// ---------- LOGIN  (SQL INJECTION - EASY) ----------
app.get('/login', (req, res) => {
  res.render('login', { error: null });
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  // VULNERABLE: raw string concatenation -> classic SQL injection
  const query = `SELECT * FROM users WHERE username='${username}' AND password='${password}'`;
  console.log('[SQL QUERY]', query);
  db.get(query, (err, row) => {
    if (err) return res.render('login', { error: 'DB error: ' + err.message });
    if (row) {
      req.session.userId = row.id;
      req.session.username = row.username;
      return res.redirect('/dashboard');
    }
    res.render('login', { error: 'Invalid credentials' });
  });
});

app.get('/dashboard', requireLogin, (req, res) => {
  res.render('dashboard', { username: req.session.username });
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login'));
});

// ---------- SEARCH  (REFLECTED XSS + SQLi ADVANCED via UNION) ----------
app.get('/search', (req, res) => {
  const q = req.query.q || '';
  // VULNERABLE: raw concatenation -> UNION-based SQL injection possible
  const query = `SELECT course, author FROM reviews WHERE course LIKE '%${q}%'`;
  console.log('[SQL QUERY]', query);
  db.all(query, (err, rows) => {
    // VULNERABLE: q is reflected straight into HTML (unescaped in view) -> Reflected XSS
    res.render('search', { q, rows: rows || [], error: err ? err.message : null });
  });
});

// ---------- BLIND BOOLEAN CHECK  (SQLi INTERMEDIATE) ----------
app.get('/check-user', (req, res) => {
  const username = req.query.username || '';
  const query = `SELECT * FROM users WHERE username='${username}'`;
  console.log('[SQL QUERY]', query);
  db.get(query, (err, row) => {
    if (err) return res.send('error: ' + err.message);
    res.send(row ? 'exists' : 'not found');
  });
});

// ---------- COURSE PAGE + REVIEWS  (STORED XSS) ----------
app.get('/course/:name', (req, res) => {
  const course = req.params.name;
  db.all(`SELECT * FROM reviews WHERE course = ?`, [course], (err, rows) => {
    res.render('course', { course, reviews: rows || [] });
  });
});

app.post('/course/:name/review', requireLogin, (req, res) => {
  const course = req.params.name;
  const { comment } = req.body;
  // Stored raw, and rendered unescaped in the view -> Stored XSS
  db.run(`INSERT INTO reviews (course, author, comment) VALUES (?, ?, ?)`,
    [course, req.session.username, comment], () => {
      res.redirect('/course/' + course);
    });
});

// ---------- PROFILE  (DOM-BASED XSS) ----------
app.get('/profile', requireLogin, (req, res) => {
  res.render('profile', { username: req.session.username });
});

// ---------- UPDATE EMAIL  (CSRF TARGET - no token check here) ----------
app.post('/update-email', requireLogin, (req, res) => {
  const { email } = req.body;
  db.run(`UPDATE users SET email = ? WHERE id = ?`, [email, req.session.userId], () => {
    res.send(`Email updated to ${email}. <a href="/dashboard">Back</a>`);
  });
});

app.listen(PORT, () => console.log(`VULNERABLE app running on http://localhost:${PORT}`));