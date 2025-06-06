const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const app = express();
const port = 3000;

app.use(express.json());

// Kết nối SQLite
const db = new sqlite3.Database('./data.db', (err) => {
  if (err) return console.error(err.message);
  console.log('✔️  Connected to SQLite database.');
});

// Tạo bảng nếu chưa có
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


// Thêm user mới
app.post('/users', (req, res) => {
  const {
    id, email, userName, passWord, status,
    fullName, phoneNumber, dob, level,
    balance, walletAddress
  } = req.body;

  const sql = `
    INSERT OR REPLACE INTO users
    (id, email, userName, passWord, status, fullName, phoneNumber, dob, level, balance, walletAddress)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `;

  db.run(sql, [
    id, email, userName, passWord, status,
    fullName, phoneNumber, dob, level,
    balance, walletAddress
  ], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ message: 'User saved', id });
  });
});

// Lấy tất cả users
app.get('/users', (req, res) => {
  const sql = `
    SELECT
      id,
      email,
      userName,
      passWord,
      status,
      fullName,
      phoneNumber,
      dob,
      level,
      balance,
      walletAddress
    FROM users
  `;

  db.all(sql, [], (err, rows) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.json(rows);
  });
});


// Khởi động server
app.listen(port, () => {
  console.log(`🚀 Server is running at http://localhost:${port}`);
});
