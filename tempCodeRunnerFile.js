const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const app = express();
const port = 3000;
const SECRET_KEY = 'supersecretkey'; // Đổi key này và giữ bí mật

app.use(cors({
  origin: 'http://127.0.0.1:3000'
}));
app.use(express.json());

// SQLite
const db = new sqlite3.Database('./data.db', (err) => {
  if (err) return console.error(err.message);
  console.log('✔️  Connected to SQLite.');
});

db.run(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT,
    userName TEXT,
    passWord TEXT,
    status TEXT,
    fullName TEXT,
    phoneNumber TEXT,
    dob TEXT,
    level INTEGER,
    balance REAL,
    walletAddress TEXT
  )
`);

// Middleware xác thực token
function verifyToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader?.split(' ')[1]; // "Bearer <token>"

  if (!token) return res.status(401).json({ error: 'Token missing' });

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;
    next();
  });
}

// Đăng nhập
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const sql = `SELECT * FROM users WHERE userName = ? OR email = ?`;

  db.get(sql, [username, username], async (err, user) => {
    if (err) return res.status(500).json({ message: 'DB error' });
    if (!user) return res.status(401).json({ message: 'User not found' });

    const isMatch = await bcrypt.compare(password, user.passWord);
    if (!isMatch) return res.status(401).json({ message: 'Wrong password' });

    const { passWord, ...safeUser } = user;

    // Tạo JWT token
    const token = jwt.sign(safeUser, SECRET_KEY, { expiresIn: '7d' });

    res.json({ user: safeUser, token });
  });
});

// Đăng ký / update user
app.post('/users', async (req, res) => {
  const {
    id, email, userName, passWord, status,
    fullName, phoneNumber, dob, level,
    balance, walletAddress
  } = req.body;

  const hashedPassword = await bcrypt.hash(passWord, 10);

  const sql = `
    INSERT OR REPLACE INTO users
    (id, email, userName, passWord, status, fullName, phoneNumber, dob, level, balance, walletAddress)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `;

  db.run(sql, [
    id, email, userName, hashedPassword, status,
    fullName, phoneNumber, dob, level,
    balance, walletAddress
  ], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ message: 'User saved', id });
  });
});

// Route cần đăng nhập mới được xem
app.get('/me', verifyToken, (req, res) => {
  res.json({ user: req.user });
});

// Route công khai: lấy danh sách user không nhạy cảm
app.get('/users', (req, res) => {
  db.all(`
    SELECT id, status, fullName, level, balance, walletAddress FROM users
  `, [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

// Start
app.listen(port, () => {
  console.log(`🚀 Server running at http://localhost:${port}`);
});
