-- seed-data.sql
-- Run this manually only if you want to reset/seed the DB yourself.
-- NOTE: server.js already auto-creates tables and seeds data on first run,
-- so this file is mainly for the assignment's submission requirement.

CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT,
  password TEXT,
  email TEXT
);

CREATE TABLE IF NOT EXISTS reviews (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  course TEXT,
  author TEXT,
  comment TEXT
);

INSERT INTO users (username, password, email) VALUES
('admin', 'admin123', 'admin@portal.com'),
('alice', 'password1', 'alice@portal.com');

INSERT INTO reviews (course, author, comment) VALUES
('CS101', 'alice', 'Great course!'),
('CS102', 'bob', 'Could be better.');
