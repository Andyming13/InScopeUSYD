// src/server.js
require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');
const { ping } = require('./db');

// 先创建 app
const app = express();

// 中间件
app.use(helmet());
app.use(express.json());
app.use(cookieParser());

// CORS（从 .env 读取，默认本地）
// CORS（多域支持：用逗号分隔）
// 例：CORS_ORIGIN=https://www.inscopei1.com.au, http://localhost:5173
const raw = process.env.CORS_ORIGIN || 'http://localhost:5173';
const ALLOWED_ORIGINS = raw.split(',').map(s => s.trim()).filter(Boolean);

app.use(cors({
  origin(origin, cb) {
    // 允许同源/无 Origin 的请求（如健康检查、curl）
    if (!origin) return cb(null, true);
    const ok = ALLOWED_ORIGINS.includes(origin);
    cb(ok ? null : new Error(`CORS blocked: ${origin}`), ok);
  },
  credentials: true,
}));

// 基础限流
const limiter = rateLimit({
  windowMs: 60_000,
  max: 120,
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(limiter);

// 健康检查（顺便测试 DB 是否可达）
app.get('/healthz', async (req, res) => {
  try {
    const now = await ping();
    res.json({ ok: true, now });
  } catch (e) {
    console.error('[DB ERROR]', e.code, e.message);
    res.status(500).json({ ok: false, error: 'DB_UNREACHABLE' });
  }
});

// 一个最简单的 API
app.get('/api/v1/hello', (req, res) => {
  res.json({ message: 'InScope API ready' });
});

// 现在再挂载路由（注意 require 路径）
const authRoutes = require('./routes/auth');
app.use('/api/v1/auth', authRoutes);

// 启动监听
const PORT = Number(process.env.PORT || 8787);
app.listen(PORT, () => {
  console.log(`InScope API listening on http://localhost:${PORT}`);
  console.log(`CORS origins allowed:`, ALLOWED_ORIGINS);
});