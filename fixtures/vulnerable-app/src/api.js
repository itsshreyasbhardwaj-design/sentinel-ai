// Intentionally insecure fixture for Sentinel AI's test suite. Do not deploy.
const express = require('express');
const { exec } = require('child_process');
const jwt = require('jsonwebtoken');
const db = require('./db');

const app = express();

// SQL injection: user id concatenated into the query.
app.get('/users/:id', (req, res) => {
  const query = `SELECT * FROM users WHERE id = ${req.params.id}`;
  db.query(query, (err, rows) => res.json(rows));
});

// Command injection: hostname interpolated into a shell command.
app.get('/ping', (req, res) => {
  exec(`ping -c 1 ${req.query.host}`, (err, stdout) => res.send(stdout));
});

// JWT signature never verified.
app.get('/me', (req, res) => {
  const claims = jwt.decode(req.headers.authorization);
  res.json({ userId: claims.sub, role: claims.role });
});

// Weak randomness used for a password reset token.
function createResetToken() {
  return Math.random().toString(36).substring(2);
}

// CORS wildcard combined with credentials.
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Credentials', 'true');
  next();
});

// Insecure session cookie.
app.use(
  require('express-session')({
    secret: 'keyboard cat',
    cookie: { httpOnly: false, secure: false },
  }),
);

// Open redirect.
app.get('/go', (req, res) => res.redirect(req.query.next));

// Reflected XSS through innerHTML on the client bundle.
function renderComment(comment) {
  document.getElementById('comments').innerHTML = comment.body;
}

// Sensitive value written to logs.
app.post('/login', (req, res) => {
  console.log('login attempt', req.body.email, 'password', req.body.password);
  res.sendStatus(200);
});

module.exports = { app, createResetToken, renderComment };
