// ============================================================
//  PHUONGIOS WEB - Backend Server (Secured)
// ============================================================
const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const crypto = require('crypto');

const CONFIG = {
  PORT: process.env.PORT || 4000,
  JWT_SECRET: process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex'),
  DB: {
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'jsphuon_shopkey',
    password: process.env.DB_PASS || 'phuongios.com',
    database: process.env.DB_NAME || 'jsphuon_shopkey',
  },
  PAY2S_ACCESS_KEY: process.env.PAY2S_ACCESS_KEY || 'e2a744f23ce1090427421c6af1df706a80389370589eea69c127c14d661d08b7',
  PAY2S_SECRET_KEY: process.env.PAY2S_SECRET_KEY || 'ee3d851ab35c7cd0164c89ac3a4c648e1f46319cebbe9a4659edb3df2026d340',
  PAY2S_WEBHOOK_TOKEN: process.env.PAY2S_WEBHOOK_TOKEN || 'cG5y77cVIhAhWGbwUCt3',
  PAY2S_ACCOUNT: '0000154878888',
  STK: '0000154878888',
  NGAN_HANG: 'MBBANK',
  PRODUCTS: [
    { id: 'FF',    category: 'game', name: 'Free Fire',              price: 150000, desc: 'Key hack Free Fire, auto update, an toàn.' },
    { id: 'LQ',    category: 'game', name: 'Liên Quân Mobile',       price: 150000, desc: 'Key hack Liên Quân, chống ban, bypass mới nhất.' },
    { id: 'BBP',   category: 'game', name: '8 Ball Pool Trollstore', price: 150000, desc: 'Key 8 Ball Pool cài qua Trollstore.' },
    { id: 'BBPI',  category: 'game', name: '8 Ball Pool IPA',        price: 220000, desc: 'Key 8 Ball Pool bản IPA, hỗ trợ mọi iOS.' },
    { id: 'CF',    category: 'game', name: 'Crossfire Legends VNG',  price: 350000, desc: 'Key hack Crossfire Legends, full tính năng.' },
    { id: 'CERT7', category: 'cert', name: 'Chứng chỉ Apple 7 ngày',  price: 50000,  desc: 'Apple Developer Certificate 7 ngày, ký IPA thoải mái.' },
    { id: 'CERT30',category: 'cert', name: 'Chứng chỉ Apple 30 ngày', price: 150000, desc: 'Apple Developer Certificate 30 ngày, ổn định.' },
    { id: 'CERT90',category: 'cert', name: 'Chứng chỉ Apple 90 ngày', price: 350000, desc: 'Apple Developer Certificate 90 ngày, tiết kiệm nhất.' },
  ],
  POLL_INTERVAL: 15000,
  ADMIN_PASSWORD: process.env.ADMIN_PASSWORD || 'phuongios@admin2026',
};

const app = express();

// ============================================================
//  SECURITY: Rate Limiter (chống brute force + DDoS)
// ============================================================
const rateLimits = {};

function rateLimit(key, maxRequests, windowMs) {
  return (req, res, next) => {
    const ip = req.ip || req.connection.remoteAddress;
    const id = key + ':' + ip;
    const now = Date.now();

    if (!rateLimits[id]) rateLimits[id] = { count: 0, resetAt: now + windowMs };

    if (now > rateLimits[id].resetAt) {
      rateLimits[id] = { count: 0, resetAt: now + windowMs };
    }

    rateLimits[id].count++;

    if (rateLimits[id].count > maxRequests) {
      const retryAfter = Math.ceil((rateLimits[id].resetAt - now) / 1000);
      res.set('Retry-After', retryAfter);
      return res.status(429).json({ error: 'Quá nhiều yêu cầu. Vui lòng thử lại sau ' + retryAfter + ' giây.' });
    }
    next();
  };
}

// Dọn rác rate limit mỗi 5 phút
setInterval(() => {
  const now = Date.now();
  for (const id in rateLimits) {
    if (now > rateLimits[id].resetAt) delete rateLimits[id];
  }
}, 300000);

// ============================================================
//  SECURITY: Headers
// ============================================================
app.use((req, res, next) => {
  res.set({
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-XSS-Protection': '1; mode=block',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
  });
  next();
});

// Rate limit chung: 100 request/phút per IP
app.use(rateLimit('global', 100, 60000));

// ============================================================
//  UDID - Phải đặt TRƯỚC express.json()
// ============================================================
app.get('/api/udid/profile', rateLimit('udid', 10, 60000), (req, res) => {
  const uuid1 = 'phuongios-' + Date.now() + '-' + Math.random().toString(36).substr(2, 8);
  const mobileconfig = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>PayloadContent</key>
    <dict>
        <key>URL</key>
        <string>https://phuongios.com/api/udid/callback</string>
        <key>DeviceAttributes</key>
        <array>
            <string>UDID</string>
            <string>IMEI</string>
            <string>ICCID</string>
            <string>VERSION</string>
            <string>PRODUCT</string>
            <string>SERIAL</string>
            <string>MAC_ADDRESS_EN0</string>
        </array>
    </dict>
    <key>PayloadOrganization</key>
    <string>PHUONGIOS</string>
    <key>PayloadDisplayName</key>
    <string>PHUONGIOS - Lấy UDID thiết bị</string>
    <key>PayloadVersion</key>
    <integer>1</integer>
    <key>PayloadUUID</key>
    <string>${uuid1}</string>
    <key>PayloadIdentifier</key>
    <string>com.phuongios.udid-profile</string>
    <key>PayloadDescription</key>
    <string>Profile tạm thời để lấy UDID thiết bị. Bạn có thể xoá profile này sau khi lấy UDID.</string>
    <key>PayloadType</key>
    <string>Profile Service</string>
</dict>
</plist>`;

  res.set({
    'Content-Type': 'application/x-apple-aspen-config',
    'Content-Disposition': 'attachment; filename="phuongios-udid.mobileconfig"',
  });
  res.send(mobileconfig);
});

app.post('/api/udid/callback', express.raw({ type: '*/*', limit: '100kb' }), (req, res) => {
  try {
    const body = req.body.toString();
    const extract = (key) => {
      const match = body.match(new RegExp(`<key>${key}</key>\\s*<string>([^<]+)</string>`));
      return match ? match[1] : '';
    };

    const udid = extract('UDID');
    const product = extract('PRODUCT');
    const version = extract('VERSION');
    const serial = extract('SERIAL');
    const imei = extract('IMEI');

    console.log('[UDID] Device:', product, '| iOS:', version, '| UDID:', udid);

    const params = new URLSearchParams({ udid, product, version, serial, imei });
    res.status(301).set('Location', '/udid.html?' + params.toString()).send();
  } catch (e) {
    console.error('[UDID] Error:', e.message);
    res.redirect('/udid.html?error=1');
  }
});

app.use(express.json({ limit: '10kb' }));
app.use(express.static(path.join(__dirname, 'phuongios')));

// ============================================================
//  DATABASE
// ============================================================
const pool = mysql.createPool({
  ...CONFIG.DB,
  waitForConnections: true,
  connectionLimit: 10,
});

async function db(sql, params = []) {
  try {
    const [rows] = await pool.query(sql, params);
    return rows;
  } catch (e) {
    console.error('[DB]', e.message);
    return null;
  }
}

async function initDB() {
  await db(`CREATE TABLE IF NOT EXISTS web_users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    balance INT DEFAULT 0,
    created_at DATETIME DEFAULT NOW()
  )`);
  await db(`CREATE TABLE IF NOT EXISTS web_deposits (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    deposit_code VARCHAR(20) UNIQUE NOT NULL,
    amount INT NOT NULL,
    status ENUM('pending','completed') DEFAULT 'pending',
    created_at DATETIME DEFAULT NOW()
  )`);
  await db(`CREATE TABLE IF NOT EXISTS web_orders (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    order_code VARCHAR(20) UNIQUE NOT NULL,
    product_id VARCHAR(20) NOT NULL,
    product_name VARCHAR(100) NOT NULL,
    amount INT NOT NULL,
    key_code TEXT DEFAULT NULL,
    status ENUM('completed','failed') DEFAULT 'completed',
    created_at DATETIME DEFAULT NOW()
  )`);
  await db(`CREATE TABLE IF NOT EXISTS key_stock (
    id INT AUTO_INCREMENT PRIMARY KEY,
    game_name VARCHAR(100) NOT NULL,
    key_code TEXT NOT NULL,
    status ENUM('available','sold') DEFAULT 'available',
    added_date DATETIME DEFAULT NOW()
  )`);
  console.log('[DB] Sẵn sàng!');
}

// ============================================================
//  AUTH MIDDLEWARE
// ============================================================
function auth(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'Chưa đăng nhập' });
  try {
    req.user = jwt.verify(token, CONFIG.JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: 'Token hết hạn' });
  }
}

// ============================================================
//  AUTH ROUTES (rate limited)
// ============================================================
app.post('/api/auth/register', rateLimit('register', 5, 300000), async (req, res) => {
  const { username, email, password } = req.body;
  if (!username || !email || !password) return res.status(400).json({ error: 'Thiếu thông tin' });

  // Validate username
  if (username.length < 3 || username.length > 30) return res.status(400).json({ error: 'Username từ 3-30 ký tự' });
  if (!/^[a-zA-Z0-9_]+$/.test(username)) return res.status(400).json({ error: 'Username chỉ chứa chữ, số và _' });

  // Validate email
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: 'Email không hợp lệ' });

  // Validate password
  if (password.length < 6 || password.length > 100) return res.status(400).json({ error: 'Mật khẩu từ 6-100 ký tự' });

  const exists = await db('SELECT id FROM web_users WHERE username = ? OR email = ?', [username, email]);
  if (exists && exists.length > 0) return res.status(400).json({ error: 'Username hoặc email đã tồn tại' });

  const hash = await bcrypt.hash(password, 10);
  const result = await db('INSERT INTO web_users (username, email, password) VALUES (?, ?, ?)', [username, email, hash]);
  if (!result) return res.status(500).json({ error: 'Lỗi tạo tài khoản' });

  const token = jwt.sign({ id: result.insertId, username }, CONFIG.JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, user: { id: result.insertId, username, email, balance: 0 } });
});

// Login: 10 lần/5 phút per IP (chống brute force)
app.post('/api/auth/login', rateLimit('login', 10, 300000), async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Thiếu thông tin' });

  const users = await db('SELECT * FROM web_users WHERE username = ? OR email = ?', [username, username]);
  if (!users || users.length === 0) return res.status(400).json({ error: 'Sai tài khoản hoặc mật khẩu' });

  const user = users[0];
  const valid = await bcrypt.compare(password, user.password);
  if (!valid) return res.status(400).json({ error: 'Sai tài khoản hoặc mật khẩu' });

  const token = jwt.sign({ id: user.id, username: user.username }, CONFIG.JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, user: { id: user.id, username: user.username, email: user.email, balance: user.balance } });
});

app.get('/api/auth/me', auth, async (req, res) => {
  const users = await db('SELECT id, username, email, balance, created_at FROM web_users WHERE id = ?', [req.user.id]);
  if (!users || users.length === 0) return res.status(404).json({ error: 'User không tồn tại' });
  res.json(users[0]);
});

// ============================================================
//  PRODUCTS
// ============================================================
app.get('/api/products', (req, res) => {
  const products = CONFIG.PRODUCTS.map(p => {
    return { ...p, priceFormatted: p.price.toLocaleString('vi-VN') + 'đ' };
  });
  res.json(products);
});

app.get('/api/products/:id/stock', async (req, res) => {
  const product = CONFIG.PRODUCTS.find(p => p.id === req.params.id);
  if (!product) return res.status(404).json({ error: 'Sản phẩm không tồn tại' });
  const stock = await db('SELECT COUNT(*) as cnt FROM key_stock WHERE game_name = ? AND status = ?', [product.name, 'available']);
  res.json({ stock: stock ? stock[0].cnt : 0 });
});

// ============================================================
//  BUY PRODUCT (rate limited: 5 lần/phút)
// ============================================================
app.post('/api/orders/buy', auth, rateLimit('buy', 5, 60000), async (req, res) => {
  const { productId } = req.body;
  const product = CONFIG.PRODUCTS.find(p => p.id === productId);
  if (!product) return res.status(400).json({ error: 'Sản phẩm không tồn tại' });

  const users = await db('SELECT balance FROM web_users WHERE id = ?', [req.user.id]);
  if (!users || users.length === 0) return res.status(400).json({ error: 'User không tồn tại' });
  if (users[0].balance < product.price) return res.status(400).json({ error: 'Số dư không đủ. Vui lòng nạp thêm tiền.' });

  const stock = await db('SELECT id, key_code FROM key_stock WHERE game_name = ? AND status = ? LIMIT 1', [product.name, 'available']);
  if (!stock || stock.length === 0) return res.status(400).json({ error: 'Hết hàng! Vui lòng quay lại sau.' });

  const key = stock[0];
  const orderCode = 'WEB' + Math.floor(100000 + Math.random() * 900000);

  const deduct = await db('UPDATE web_users SET balance = balance - ? WHERE id = ? AND balance >= ?', [product.price, req.user.id, product.price]);
  if (!deduct || deduct.affectedRows === 0) return res.status(400).json({ error: 'Số dư không đủ' });

  const markSold = await db('UPDATE key_stock SET status = ? WHERE id = ? AND status = ?', ['sold', key.id, 'available']);
  if (!markSold || markSold.affectedRows === 0) {
    await db('UPDATE web_users SET balance = balance + ? WHERE id = ?', [product.price, req.user.id]);
    return res.status(400).json({ error: 'Key đã được bán. Vui lòng thử lại.' });
  }

  await db('INSERT INTO web_orders (user_id, order_code, product_id, product_name, amount, key_code) VALUES (?, ?, ?, ?, ?, ?)',
    [req.user.id, orderCode, product.id, product.name, product.price, key.key_code]);

  const updated = await db('SELECT balance FROM web_users WHERE id = ?', [req.user.id]);

  res.json({
    order_code: orderCode,
    product: product.name,
    key_code: key.key_code,
    amount: product.price,
    balance: updated ? updated[0].balance : 0,
  });
});

// ============================================================
//  ORDERS HISTORY
// ============================================================
app.get('/api/orders', auth, async (req, res) => {
  const orders = await db(
    'SELECT order_code, product_name, amount, key_code, status, created_at FROM web_orders WHERE user_id = ? ORDER BY created_at DESC LIMIT 50',
    [req.user.id]
  );
  res.json(orders || []);
});

// ============================================================
//  DEPOSIT (rate limited: 5 lần/phút)
// ============================================================
app.post('/api/deposit/create', auth, rateLimit('deposit', 5, 60000), async (req, res) => {
  const { amount } = req.body;
  if (!amount || amount < 10000) return res.status(400).json({ error: 'Số tiền tối thiểu 10.000đ' });
  if (amount > 10000000) return res.status(400).json({ error: 'Số tiền tối đa 10.000.000đ' });

  const depositCode = 'NAP' + Math.floor(100000 + Math.random() * 900000);

  const result = await db('INSERT INTO web_deposits (user_id, deposit_code, amount) VALUES (?, ?, ?)',
    [req.user.id, depositCode, amount]);
  if (!result) return res.status(500).json({ error: 'Lỗi tạo lệnh nạp' });

  const qrUrl = 'https://img.vietqr.io/image/' + CONFIG.NGAN_HANG + '-' + CONFIG.STK +
    '-compact2.png?amount=' + amount + '&addInfo=' + depositCode + '&accountName=PHUONGIOS';

  res.json({
    deposit_code: depositCode,
    amount,
    qr_url: qrUrl,
    bank: CONFIG.NGAN_HANG,
    stk: CONFIG.STK,
  });
});

app.get('/api/deposit/history', auth, async (req, res) => {
  const deposits = await db(
    'SELECT deposit_code, amount, status, created_at FROM web_deposits WHERE user_id = ? ORDER BY created_at DESC LIMIT 20',
    [req.user.id]
  );
  res.json(deposits || []);
});

// ============================================================
//  PAY2S WEBHOOK (xác thực token)
// ============================================================
app.post('/webhook/pay2s', async (req, res) => {
  // Xác thực webhook token từ Pay2S
  const webhookToken = req.headers['x-webhook-token'] || req.query.token || '';
  if (webhookToken !== CONFIG.PAY2S_WEBHOOK_TOKEN) {
    console.log('[WEBHOOK] Token không hợp lệ:', webhookToken);
    return res.status(403).json({ error: 'Forbidden' });
  }

  console.log('[WEBHOOK]', JSON.stringify(req.body));
  res.json({ success: true });

  try {
    const { transactions } = req.body;
    if (!transactions || !Array.isArray(transactions)) return;

    for (const trans of transactions) {
      const content = (trans.content || trans.description || '').toUpperCase();
      const amount = trans.transferAmount || trans.amount || 0;
      const transferType = trans.transferType || trans.type || 'IN';
      if (transferType !== 'IN') continue;

      const napMatch = content.match(/NAP\d+/);
      if (napMatch) {
        const depositCode = napMatch[0];
        console.log('[WEBHOOK] Deposit:', depositCode, amount);

        const deps = await db('SELECT id, user_id, amount FROM web_deposits WHERE deposit_code = ? AND status = ? LIMIT 1',
          [depositCode, 'pending']);
        if (!deps || deps.length === 0) continue;

        const dep = deps[0];
        if (amount < dep.amount) {
          console.log('[WEBHOOK] Số tiền không đủ:', amount, '<', dep.amount);
          continue;
        }

        await db('UPDATE web_deposits SET status = ? WHERE id = ?', ['completed', dep.id]);
        await db('UPDATE web_users SET balance = balance + ? WHERE id = ?', [dep.amount, dep.user_id]);
        console.log('[WEBHOOK] Nạp thành công! User:', dep.user_id, 'Amount:', dep.amount);
        continue;
      }

      const ordMatch = content.match(/ORD\d+/);
      if (ordMatch) {
        console.log('[WEBHOOK] Bot order:', ordMatch[0], '- skip (bot xử lý)');
      }
    }
  } catch (e) {
    console.error('[WEBHOOK] Error:', e.message);
  }
});

app.get('/webhook/pay2s', (req, res) => res.json({ success: true }));

// ============================================================
//  PAY2S POLLING
// ============================================================
let pay2sToken = null;
let pay2sTokenExp = 0;
let lastProcessedId = 0;

async function getPay2sToken() {
  if (pay2sToken && Date.now() < pay2sTokenExp) return pay2sToken;
  try {
    const basic = Buffer.from(CONFIG.PAY2S_ACCESS_KEY + ':' + CONFIG.PAY2S_SECRET_KEY).toString('base64');
    const res = await fetch('https://api-partner.pay2s.vn/v1/auth/authorize', {
      method: 'POST',
      headers: { 'Authorization': 'Basic ' + basic, 'Content-Type': 'application/json' },
    });
    const data = await res.json();
    if (data.success && data.data) {
      pay2sToken = data.data.access_token;
      pay2sTokenExp = Date.now() + (data.data.expires_in - 60) * 1000;
      return pay2sToken;
    }
  } catch (e) {
    console.error('[POLL] Token error:', e.message);
  }
  return null;
}

async function pollDeposits() {
  try {
    const token = await getPay2sToken();
    if (!token) return;

    const res = await fetch(
      'https://api-partner.pay2s.vn/v1/transactions?accountNumber=' + CONFIG.PAY2S_ACCOUNT,
      { headers: { 'Authorization': 'Bearer ' + token } }
    );
    const data = await res.json();
    if (!data.status || !data.transactions) return;

    const newTrans = data.transactions
      .filter(t => t.id > lastProcessedId && (t.type === 'IN' || t.transferType === 'IN'))
      .reverse();

    for (const trans of newTrans) {
      const content = (trans.description || trans.content || '').toUpperCase();
      const amount = trans.transferAmount || trans.amount || 0;

      const napMatch = content.match(/NAP\d+/);
      if (napMatch) {
        const depositCode = napMatch[0];
        const deps = await db('SELECT id, user_id, amount FROM web_deposits WHERE deposit_code = ? AND status = ? LIMIT 1',
          [depositCode, 'pending']);
        if (deps && deps.length > 0) {
          const dep = deps[0];
          if (amount >= dep.amount) {
            await db('UPDATE web_deposits SET status = ? WHERE id = ?', ['completed', dep.id]);
            await db('UPDATE web_users SET balance = balance + ? WHERE id = ?', [dep.amount, dep.user_id]);
            console.log('[POLL] Nạp thành công! User:', dep.user_id, 'Amount:', dep.amount);
          }
        }
      }

      lastProcessedId = Math.max(lastProcessedId, trans.id);
    }

    if (data.transactions.length > 0 && lastProcessedId === 0) {
      lastProcessedId = data.transactions[0].id;
    }
  } catch (e) {
    console.error('[POLL]', e.message);
  }
}

// ============================================================
//  ADMIN API
// ============================================================
function adminAuth(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'Chưa đăng nhập admin' });
  try {
    const decoded = jwt.verify(token, CONFIG.JWT_SECRET);
    if (!decoded.isAdmin) return res.status(403).json({ error: 'Không có quyền admin' });
    req.admin = decoded;
    next();
  } catch {
    return res.status(401).json({ error: 'Token hết hạn' });
  }
}

// Admin login
app.post('/api/admin/login', rateLimit('admin-login', 5, 300000), (req, res) => {
  const { password } = req.body;
  if (password !== CONFIG.ADMIN_PASSWORD) return res.status(401).json({ error: 'Sai mật khẩu admin' });
  const token = jwt.sign({ isAdmin: true }, CONFIG.JWT_SECRET, { expiresIn: '24h' });
  res.json({ token });
});

// Dashboard stats
app.get('/api/admin/stats', adminAuth, async (req, res) => {
  const users = await db('SELECT COUNT(*) as cnt FROM web_users');
  const orders = await db('SELECT COUNT(*) as cnt, COALESCE(SUM(amount),0) as total FROM web_orders');
  const deposits = await db('SELECT COUNT(*) as cnt, COALESCE(SUM(amount),0) as total FROM web_deposits WHERE status="completed"');
  const keys = await db('SELECT COUNT(*) as cnt FROM key_stock WHERE status="available"');
  res.json({
    totalUsers: users?.[0]?.cnt || 0,
    totalOrders: orders?.[0]?.cnt || 0,
    totalRevenue: orders?.[0]?.total || 0,
    totalDeposits: deposits?.[0]?.total || 0,
    availableKeys: keys?.[0]?.cnt || 0,
  });
});

// Danh sách users
app.get('/api/admin/users', adminAuth, async (req, res) => {
  const users = await db('SELECT id, username, email, balance, created_at FROM web_users ORDER BY id DESC LIMIT 100');
  res.json(users || []);
});

// Sửa balance user
app.post('/api/admin/users/:id/balance', adminAuth, async (req, res) => {
  const { balance } = req.body;
  if (balance === undefined || balance < 0) return res.status(400).json({ error: 'Balance không hợp lệ' });
  await db('UPDATE web_users SET balance = ? WHERE id = ?', [balance, req.params.id]);
  res.json({ success: true });
});

// Danh sách đơn hàng
app.get('/api/admin/orders', adminAuth, async (req, res) => {
  const orders = await db(`SELECT o.*, u.username FROM web_orders o
    LEFT JOIN web_users u ON o.user_id = u.id
    ORDER BY o.created_at DESC LIMIT 100`);
  res.json(orders || []);
});

// Danh sách key stock
app.get('/api/admin/keys', adminAuth, async (req, res) => {
  const keys = await db('SELECT * FROM key_stock ORDER BY id DESC LIMIT 200');
  res.json(keys || []);
});

// Thêm key
app.post('/api/admin/keys', adminAuth, async (req, res) => {
  const { game_name, keys } = req.body;
  if (!game_name || !keys) return res.status(400).json({ error: 'Thiếu thông tin' });

  const keyList = keys.split('\n').map(k => k.trim()).filter(k => k.length > 0);
  if (keyList.length === 0) return res.status(400).json({ error: 'Không có key nào' });

  let added = 0;
  for (const key of keyList) {
    const result = await db('INSERT INTO key_stock (game_name, key_code, status) VALUES (?, ?, "available")', [game_name, key]);
    if (result) added++;
  }
  res.json({ success: true, added });
});

// Xoá key
app.delete('/api/admin/keys/:id', adminAuth, async (req, res) => {
  await db('DELETE FROM key_stock WHERE id = ?', [req.params.id]);
  res.json({ success: true });
});

// Lấy sản phẩm + giá hiện tại
app.get('/api/admin/products', adminAuth, (req, res) => {
  res.json(CONFIG.PRODUCTS);
});

// Sửa giá sản phẩm
app.post('/api/admin/products/:id/price', adminAuth, (req, res) => {
  const { price } = req.body;
  if (!price || price < 0) return res.status(400).json({ error: 'Giá không hợp lệ' });
  const product = CONFIG.PRODUCTS.find(p => p.id === req.params.id);
  if (!product) return res.status(404).json({ error: 'Sản phẩm không tồn tại' });
  product.price = price;
  res.json({ success: true, product });
});

// Sửa mô tả sản phẩm
app.post('/api/admin/products/:id/update', adminAuth, (req, res) => {
  const { price, desc, name } = req.body;
  const product = CONFIG.PRODUCTS.find(p => p.id === req.params.id);
  if (!product) return res.status(404).json({ error: 'Sản phẩm không tồn tại' });
  if (price !== undefined) product.price = price;
  if (desc) product.desc = desc;
  if (name) product.name = name;
  res.json({ success: true, product });
});

// Danh sách nạp tiền
app.get('/api/admin/deposits', adminAuth, async (req, res) => {
  const deposits = await db(`SELECT d.*, u.username FROM web_deposits d
    LEFT JOIN web_users u ON d.user_id = u.id
    ORDER BY d.created_at DESC LIMIT 100`);
  res.json(deposits || []);
});

// ============================================================
//  HEALTH (ẩn thông tin nhạy cảm)
// ============================================================
app.get('/api/health', (req, res) => {
  res.json({ status: 'OK' });
});

// SPA fallback
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'phuongios', 'index.html'));
});

// ============================================================
//  START
// ============================================================
async function main() {
  await initDB();
  app.listen(CONFIG.PORT, '0.0.0.0', () => {
    console.log('[SERVER] http://localhost:' + CONFIG.PORT);
  });
  setInterval(pollDeposits, CONFIG.POLL_INTERVAL);
  console.log('[POLL] Kiểm tra GD mỗi ' + (CONFIG.POLL_INTERVAL / 1000) + 's/lần');
}

main().catch(console.error);
