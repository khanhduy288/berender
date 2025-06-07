const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');  // thêm cors
const app = express();
const port = 3000;
const crypto = require('crypto'); // Nếu bạn muốn mã hóa mật khẩu (tùy chọn)

// CORS config - cho phép frontend localhost (hoặc bạn đổi thành domain frontend của bạn)
app.use(cors({
  origin: 'http://127.0.0.1:3000'  // hoặc '*' nếu bạn muốn mở rộng
}));

app.use(express.json());

// Middleware kiểm tra secret key
app.use((req, res, next) => {
  const key = req.headers['x-secret-key'];
  if (key !== 'adminsepuser') {
    return res.status(403).json({ error: 'Forbidden, invalid secret key' });
  }
  next();
});

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

// Thêm user mới (hoặc update nếu id trùng)
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

// Lấy tất cả users (chỉ lấy các trường không nhạy cảm)
app.get('/users', (req, res) => {
  const sql = `
    SELECT
      id, status, fullName,
      level, balance, walletAddress
    FROM users
  `;

  db.all(sql, [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

// Lấy thông tin user theo ID (không trả userName, passWord)
app.get('/users/:id', (req, res) => {
  const id = req.params.id;
  const sql = `
    SELECT
      id, status, fullName,
      level, balance, walletAddress
    FROM users
    WHERE id = ?
  `;

  db.get(sql, [id], (err, row) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!row) return res.status(404).json({ error: 'User not found' });
    res.json(row);
  });
});

// Cập nhật user theo id
app.put('/users/:id', (req, res) => {
  const id = req.params.id;
  const {
    email, userName, passWord, status,
    fullName, phoneNumber, dob, level,
    balance, walletAddress
  } = req.body;

  const sql = `
    UPDATE users SET
      email = ?,
      userName = ?,
      passWord = ?,
      status = ?,
      fullName = ?,
      phoneNumber = ?,
      dob = ?,
      level = ?,
      balance = ?,
      walletAddress = ?
    WHERE id = ?
  `;

  db.run(sql, [
    email, userName, passWord, status,
    fullName, phoneNumber, dob, level,
    balance, walletAddress, id
  ], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    if (this.changes === 0) return res.status(404).json({ error: 'User not found' });
    res.json({ message: 'User updated', id });
  });
});

// Xóa user theo id
app.delete('/users/:id', (req, res) => {
  const id = req.params.id;
  const sql = `DELETE FROM users WHERE id = ?`;

  db.run(sql, [id], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    if (this.changes === 0) return res.status(404).json({ error: 'User not found' });
    res.json({ message: 'User deleted', id });
  });
});

// Start server
app.listen(port, () => {
  console.log(`🚀 Server is running at http://localhost:${port}`);
});


// API login - POST /login
app.post('/login', (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required.' });
  }

  // Query user theo username/email (đơn giản, bạn có thể tùy chỉnh thêm)
  const sql = `
    SELECT * FROM users
    WHERE userName = ? OR email = ?
    LIMIT 1
  `;

  db.get(sql, [username, username], (err, user) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: 'Internal server error.' });
    }

    if (!user) {
      return res.status(401).json({ error: 'Invalid username or password.' });
    }

    // So sánh mật khẩu (nếu bạn mã hóa thì phải giải mã hoặc băm lại để so sánh)
    if (user.passWord !== password) {
      return res.status(401).json({ error: 'Invalid username or password.' });
    }

    // Nếu đúng, trả về user info (bỏ passWord) hoặc token nếu có
    const { passWord, ...userInfo } = user;

    res.json({
      message: 'Login successful',
      user: userInfo
      // token: '...' // nếu bạn muốn thêm JWT hoặc token ở đây
    });
  });
});