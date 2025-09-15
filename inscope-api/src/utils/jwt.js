// src/utils/jwt.js
const jwt = require('jsonwebtoken');

const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret_key';
const ACCESS_EXPIRES_IN = '15m';    // access token 有效期
const REFRESH_EXPIRES_IN = '7d';    // refresh token 有效期

function signAccessToken(user) {
  return jwt.sign(
    { uid: user.id, username: user.username, email: user.email },
    JWT_SECRET,
    { expiresIn: ACCESS_EXPIRES_IN }
  );
}

function signRefreshToken(user) {
  return jwt.sign(
    { uid: user.id },
    JWT_SECRET,
    { expiresIn: REFRESH_EXPIRES_IN }
  );
}

function verifyToken(token) {
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch (err) {
    return null;
  }
}

module.exports = {
  signAccessToken,
  signRefreshToken,
  verifyToken,
};