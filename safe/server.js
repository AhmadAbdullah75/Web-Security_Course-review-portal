const express = require('express');
const session = require('express-session');
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const csrf = require('csurf');
const path = require('path');

const app = express();
const PORT = 3001;
const db = new sqlite3.Database(path.join(__dirname, 'database.db'));

app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());

// FIX: SameSite cookie -> mitigates CSRF
app.use(session({
  secret: 'safe-secret-key',
  resave: false,
  saveUninitialized: true,
  cookie: { sameSite: 'strict' }
}));

const csrfProtection = csrf();

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

// ---------- LOGIN  (FIX: parameterized query) ----------
app.get('/login', csrfProtection, (req, res) => {
  res.render('login', { error: null, csrfToken: req.csrfToken() });
});

app.post('/login', csrfProtection, (req, res) => {
  const { username, password } = req.body;
  db.get(`SELECT * FROM users WHERE username = ? AND password = ?`, [username, password], (err, row) => {
    if (row) {
      req.session.userId = row.id;
      req.session.username = row.username;
      return res.redirect('/dashboard');
    }
    res.render('login', { error: 'Invalid credentials', csrfToken: req.csrfToken() });
  });
});

app.get('/dashboard', requireLogin, (req, res) => {
  res.render('dashboard', { username: req.session.username });
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login'));
});

// ---------- SEARCH  (FIX: parameterized query + auto-escaped output) ----------
app.get('/search', (req, res) => {
  const q = req.query.q || '';
  db.all(`SELECT course, author FROM reviews WHERE course LIKE ?`, [`%${q}%`], (err, rows) => {
    res.render('search', { q, rows: rows || [], error: err ? 'Invalid input' : null });
  });
});

// ---------- BLIND BOOLEAN CHECK  (FIX: parameterized) ----------
app.get('/check-user', (req, res) => {
  const username = req.query.username || '';
  db.get(`SELECT * FROM users WHERE username = ?`, [username], (err, row) => {
    res.send(row ? 'exists' : 'not found');
  });
});

// ---------- COURSE PAGE + REVIEWS  (FIX: escaped output -> no Stored XSS) ----------
app.get('/course/:name', (req, res) => {
  const course = req.params.name;
  db.all(`SELECT * FROM reviews WHERE course = ?`, [course], (err, rows) => {
    res.render('course', { course, reviews: rows || [] });
  });
});

app.post('/course/:name/review', requireLogin, (req, res) => {
  const course = req.params.name;
  const { comment } = req.body;
  db.run(`INSERT INTO reviews (course, author, comment) VALUES (?, ?, ?)`,
    [course, req.session.username, comment], () => {
      res.redirect('/course/' + course);
    });
});

// ---------- PROFILE  (FIX: textContent instead of innerHTML -> no DOM XSS) ----------
app.get('/profile', requireLogin, csrfProtection, (req, res) => {
  res.render('profile', { username: req.session.username, csrfToken: req.csrfToken() });
});

// ---------- UPDATE EMAIL  (FIX: CSRF token required) ----------
app.post('/update-email', requireLogin, csrfProtection, (req, res) => {
  const { email } = req.body;
  db.run(`UPDATE users SET email = ? WHERE id = ?`, [email, req.session.userId], () => {
    res.send(`Email updated to ${email}. <a href="/dashboard">Back</a>`);
  });
});

// CSRF error handler -> shows the attack being blocked
app.use((err, req, res, next) => {
  if (err.code === 'EBADCSRFTOKEN') {
    return res.status(403).send('Forbidden: invalid or missing CSRF token (attack blocked)');
  }
  next(err);
});

app.listen(PORT, () => console.log(`SAFE app running on http://localhost:${PORT}`));