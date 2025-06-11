const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const app = express();
const port = 3000;
const SECRET_KEY = 'adminsepuser'; 
const allowedOrigins = [
  'http://127.0.0.1:3000',
  'https://antique-chi.vercel.app'
];

app.use(cors({
  origin: function (origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true // nếu bạn cần gửi cookie/token
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

function verifyApiKey(req, res, next) {
  const apiKey = req.headers['x-api-key'];
  if (apiKey !== SECRET_KEY) {
    return res.status(403).json({ error: 'Invalid API Key' });
  }
  next();
}

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
app.get('/users',verifyApiKey, (req, res) => {
  db.all(`
    SELECT id, status, fullName, level, balance, exp , walletAddress FROM users
  `, [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

// Lấy thông tin 1 user theo ID
app.get('/users/:id',verifyApiKey, (req, res) => {
  const userId = req.params.id;

  db.get(`SELECT id, status, fullName, level, balance, exp, walletAddress FROM users WHERE id = ?`, [userId], (err, row) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!row) return res.status(404).json({ message: 'User not found' });
    res.json(row);
  });
});

// Cập nhật user theo ID (PUT)
app.put('/users/:id',verifyApiKey, async (req, res) => {
  const userId = req.params.id;
  const {
    email, userName, passWord, status,
    fullName, phoneNumber, dob, level,
    balance, walletAddress, exp  // thêm exp ở đây
  } = req.body;

  const hashedPassword = passWord ? await bcrypt.hash(passWord, 10) : null;

  db.run(`
    UPDATE users SET
      email = ?, userName = ?, ${hashedPassword ? 'passWord = ?,' : ''}
      status = ?, fullName = ?, phoneNumber = ?, dob = ?, level = ?, balance = ?, walletAddress = ?, exp = ?
    WHERE id = ?
  `,
  hashedPassword
    ? [email, userName, hashedPassword, status, fullName, phoneNumber, dob, level, balance, walletAddress, exp, userId]
    : [email, userName, status, fullName, phoneNumber, dob, level, balance, walletAddress, exp, userId],
  function(err) {
    if (err) return res.status(500).json({ error: err.message });
    if (this.changes === 0) return res.status(404).json({ message: 'User not found' });
    res.json({ message: 'User updated' });
  });
});


// Xoá user theo ID
app.delete('/users/:id',verifyApiKey, (req, res) => {
  const userId = req.params.id;

  db.run(`DELETE FROM users WHERE id = ?`, [userId], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    if (this.changes === 0) return res.status(404).json({ message: 'User not found' });
    res.json({ message: 'User deleted' });
  });
});



app.get('/ping', (req, res) => {
  res.sendStatus(200);
});
// Start
app.listen(port, () => {
  console.log(`🚀 Server running at http://localhost:${port}`);
});
