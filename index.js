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
  'https://antique-chi.vercel.app',
  'https://boatfun.io',
  'https://www.boatfun.io'
];

app.use(cors({
  origin: function (origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true 
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

db.run(`
  CREATE TABLE IF NOT EXISTS matches (
    id TEXT PRIMARY KEY,
    name TEXT,
    team1 TEXT,
    team2 TEXT,
    option1 TEXT,
    option2 TEXT,
    rate1 REAL,
    rate2 REAL,
    status1 TEXT,
    status2 TEXT,
    claim TEXT,
    time TEXT,
    iframe TEXT,
    countdown TEXT,
    sum1 REAL,
    sum2 REAL,
    status TEXT,
    creatorId TEXT,
    winningTeam TEXT
  )
`);

db.run(`
  CREATE TABLE IF NOT EXISTS orders (
    id TEXT PRIMARY KEY,
    matchId TEXT,
    matchName TEXT,
    team TEXT,
    amount REAL,
    userWallet TEXT,
    token TEXT,
    timestamp TEXT,
    status TEXT,
    txHash TEXT,
    claim REAL,
    refund REAL,
    option TEXT,
    processStart TEXT,
    countdownEnd INTEGER,
    hasAutoBet BOOLEAN
  )
`);



function verifyToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader?.split(' ')[1]; 

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

const { passWord, ...userData } = user;
if ('exp' in userData) delete userData.exp;

const token = jwt.sign(userData, SECRET_KEY, { expiresIn: '7d' });


res.json({ user: userData, token });
  });
});

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

app.get('/me', verifyToken, (req, res) => {
  const userId = req.user.id;

  db.get(`SELECT * FROM users WHERE id = ?`, [userId], (err, row) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    if (!row) return res.status(404).json({ message: 'User not found' });

    const { passWord, ...userWithoutPassword } = row;
    res.json({ user: userWithoutPassword });
  });
});

app.get('/users',verifyApiKey, (req, res) => {
  db.all(`
    SELECT id, status, fullName, level, balance, exp , walletAddress FROM users
  `, [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.get('/users/:id',verifyApiKey, (req, res) => {
  const userId = req.params.id;

  db.get(`SELECT id, status, fullName, level, balance, exp, walletAddress FROM users WHERE id = ?`, [userId], (err, row) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!row) return res.status(404).json({ message: 'User not found' });
    res.json(row);
  });
});

app.patch('/users/:id/status', verifyApiKey, (req, res) => {
  const userId = req.params.id;
  const { status } = req.body;
  db.run(`UPDATE users SET status = ? WHERE id = ?`, [status, userId], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ message: 'Status updated' });
  });
});

app.get('/users/by-wallet/:walletAddress', verifyApiKey, (req, res) => {
  const wallet = req.params.walletAddress;
  db.get(`SELECT * FROM users WHERE walletAddress = ?`, [wallet], (err, user) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!user) return res.status(404).json({ message: 'User not found' });
    const { passWord, ...userData } = user;
    res.json(userData);
  });
});



app.put('/users/:id',verifyApiKey, async (req, res) => {
  const userId = req.params.id;
  const {
    email, userName, passWord, status,
    fullName, phoneNumber, dob, level,
    balance, walletAddress, exp  
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


app.delete('/users/:id',verifyApiKey, (req, res) => {
  const userId = req.params.id;

  db.run(`DELETE FROM users WHERE id = ?`, [userId], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    if (this.changes === 0) return res.status(404).json({ message: 'User not found' });
    res.json({ message: 'User deleted' });
  });
});

app.patch('/users/:id', verifyApiKey, (req, res) => {
  const userId = req.params.id;
  const updates = req.body;

  const allowedFields = ['email', 'userName', 'status', 'fullName', 'phoneNumber', 'dob', 'level', 'balance', 'walletAddress', 'exp'];
  const fieldsToUpdate = Object.keys(updates).filter(field => allowedFields.includes(field));

  if (fieldsToUpdate.length === 0) {
    return res.status(400).json({ error: 'No valid fields to update' });
  }

  const setClause = fieldsToUpdate.map(field => `${field} = ?`).join(', ');
  const values = fieldsToUpdate.map(field => updates[field]);

  const sql = `UPDATE users SET ${setClause} WHERE id = ?`;

  db.run(sql, [...values, userId], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    if (this.changes === 0) return res.status(404).json({ message: 'User not found' });
    res.json({ message: 'User partially updated' });
  });
});

// CREATE match
app.post('/matches', verifyApiKey, (req, res) => {
  const {
    id, name, team1, team2, option1, option2,
    rate1, rate2, status1, status2, claim, time,
    iframe, countdown, sum1, sum2, status, creatorId, winningTeam
  } = req.body;

  const sql = `
    INSERT OR REPLACE INTO matches (
      id, name, team1, team2, option1, option2,
      rate1, rate2, status1, status2, claim, time,
      iframe, countdown, sum1, sum2, status, creatorId, winningTeam
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `;

  db.run(sql, [
    id, name, team1, team2, option1, option2,
    rate1, rate2, status1, status2, claim, time,
    iframe, countdown, sum1, sum2, status, creatorId, winningTeam
  ], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ message: 'Match created', id });
  });
});

// READ all matches
app.get('/matches', (req, res) => {
  db.all(`SELECT * FROM matches`, [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

// READ one match
app.get('/matches/:id', (req, res) => {
  const matchId = req.params.id;
  db.get(`SELECT * FROM matches WHERE id = ?`, [matchId], (err, row) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!row) return res.status(404).json({ message: 'Match not found' });
    res.json(row);
  });
});

// UPDATE match toàn bộ
app.put('/matches/:id', verifyApiKey, (req, res) => {
  const matchId = req.params.id;
  const {
    name, team1, team2, option1, option2,
    rate1, rate2, status1, status2, claim, time,
    iframe, countdown, sum1, sum2, status, creatorId, winningTeam
  } = req.body;

  const sql = `
    UPDATE matches SET
      name = ?, team1 = ?, team2 = ?, option1 = ?, option2 = ?,
      rate1 = ?, rate2 = ?, status1 = ?, status2 = ?, claim = ?, time = ?,
      iframe = ?, countdown = ?, sum1 = ?, sum2 = ?, status = ?, creatorId = ?, winningTeam = ?
    WHERE id = ?
  `;

  db.run(sql, [
    name, team1, team2, option1, option2,
    rate1, rate2, status1, status2, claim, time,
    iframe, countdown, sum1, sum2, status, creatorId, winningTeam,
    matchId
  ], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    if (this.changes === 0) return res.status(404).json({ message: 'Match not found' });
    res.json({ message: 'Match updated' });
  });
});

// PATCH match một phần
app.patch('/matches/:id', verifyApiKey, (req, res) => {
  const matchId = req.params.id;
  const updates = req.body;

  const allowedFields = [
    'name', 'team1', 'team2', 'option1', 'option2',
    'rate1', 'rate2', 'status1', 'status2', 'claim', 'time',
    'iframe', 'countdown', 'sum1', 'sum2', 'status', 'creatorId', 'winningTeam'
  ];
  const fieldsToUpdate = Object.keys(updates).filter(field => allowedFields.includes(field));

  if (fieldsToUpdate.length === 0) {
    return res.status(400).json({ error: 'No valid fields to update' });
  }

  const setClause = fieldsToUpdate.map(field => `${field} = ?`).join(', ');
  const values = fieldsToUpdate.map(field => updates[field]);

  const sql = `UPDATE matches SET ${setClause} WHERE id = ?`;

  db.run(sql, [...values, matchId], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    if (this.changes === 0) return res.status(404).json({ message: 'Match not found' });
    res.json({ message: 'Match partially updated' });
  });
});

// DELETE match
app.delete('/matches/:id', verifyApiKey, (req, res) => {
  const matchId = req.params.id;

  db.run(`DELETE FROM matches WHERE id = ?`, [matchId], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    if (this.changes === 0) return res.status(404).json({ message: 'Match not found' });
    res.json({ message: 'Match deleted' });
  });
});



// Lấy tất cả đơn
app.get('/orders', verifyApiKey, (req, res) => {
  const { matchId, userWallet } = req.query;
  let sql = 'SELECT * FROM orders';
  const params = [];

  if (matchId && userWallet) {
    sql += ' WHERE matchId = ? AND userWallet = ?';
    params.push(matchId, userWallet);
  } else if (matchId) {
    sql += ' WHERE matchId = ?';
    params.push(matchId);
  } else if (userWallet) {
    sql += ' WHERE userWallet = ?';
    params.push(userWallet);
  }

  db.all(sql, params, (err, rows) => {
    if (err) return res.status(500).json({ message: 'DB error' });
    res.json(rows);
  });
});



// Lấy đơn theo ID
app.get('/orders/:id', (req, res) => {
  db.get(`SELECT * FROM orders WHERE id = ?`, [req.params.id], (err, row) => {
    if (err) return res.status(500).json({ message: 'DB error' });
    if (!row) return res.status(404).json({ message: 'Order not found' });
    res.json(row);
  });
});

// Tạo đơn mới
app.post('/orders', (req, res) => {
  const {
    id, matchId, matchName, team, amount, userWallet,
    token, timestamp, status, txHash, claim, refund,
    option, processStart, countdownEnd, hasAutoBet
  } = req.body;

  db.run(`
    INSERT INTO orders (
      id, matchId, matchName, team, amount, userWallet, token, timestamp,
      status, txHash, claim, refund, option, processStart, countdownEnd, hasAutoBet
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `,
  [
    id, matchId, matchName, team, amount, userWallet, token, timestamp,
    status, txHash, claim, refund, option, processStart, countdownEnd, hasAutoBet ? 1 : 0
  ],
  function (err) {
    if (err) return res.status(500).json({ message: 'DB insert error', error: err });
    res.json({ message: 'Order created', id });
  });
});

// Cập nhật đơn
app.patch('/orders/:id', (req, res) => {
  const fields = Object.entries(req.body)
    .filter(([_, value]) => value !== undefined)
    .map(([key]) => `${key} = ?`);
  const values = Object.values(req.body);

  if (fields.length === 0) return res.status(400).json({ message: 'No data to update' });

  db.run(
    `UPDATE orders SET ${fields.join(', ')} WHERE id = ?`,
    [...values, req.params.id],
    function (err) {
      if (err) return res.status(500).json({ message: 'DB update error' });
      res.json({ message: 'Order updated', changes: this.changes });
    }
  );
});

// Xóa đơn
app.delete('/orders/:id', (req, res) => {
  db.run(`DELETE FROM orders WHERE id = ?`, [req.params.id], function (err) {
    if (err) return res.status(500).json({ message: 'DB delete error' });
    res.json({ message: 'Order deleted', changes: this.changes });
  });
});




app.get('/ping', (req, res) => {
  res.sendStatus(200);
});

app.listen(port, () => {
  console.log(`🚀 Server running at http://localhost:${port}`);
});
