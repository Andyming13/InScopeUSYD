// src/utils/jwt.js
const crypto = require('crypto');
const argon2 = require('argon2');
const jwt = require('jsonwebtoken');

function signAccessToken(payload, ttl = '15m') {
  return jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: ttl });
}

function verifyJWT(token) {
  return jwt.verify(token, process.env.JWT_SECRET);
}

function randomToken(bytes = 32) {
  return crypto.randomBytes(bytes).toString('base64url');
}

async function hashToken(token) {
  return argon2.hash(token, { type: argon2.argon2id });
}

function setRefreshCookie(res, token) {
  const isProd = process.env.NODE_ENV === 'production';
  res.cookie('rt', token, {
    httpOnly: true,
    secure: isProd,           // 生产环境要求 HTTPS
    sameSite: isProd ? 'Strict' : 'Lax',
    path: '/api/v1/auth',
    maxAge: 30 * 24 * 60 * 60 * 1000, // 30d
  });
}

module.exports = { signAccessToken, verifyJWT, randomToken, hashToken, setRefreshCookie };