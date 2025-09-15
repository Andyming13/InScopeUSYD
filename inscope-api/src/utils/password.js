// src/utils/password.js
const argon2 = require('argon2');

/** 用户名：3–20 位，仅字母/数字/下划线 */
function validateUsername(u) {
  return typeof u === 'string' && /^[a-zA-Z0-9_]{3,20}$/.test(u);
}

/** 密码强度检查：≥8 且含 大写/小写/数字/符号，且不包含邮箱前缀/用户名 */
function checkPasswordStrength({ password, email, username }) {
  const errs = [];
  if (!password || password.length < 8) errs.push('长度至少 8 位');
  if (!/[A-Z]/.test(password)) errs.push('需包含大写字母');
  if (!/[a-z]/.test(password)) errs.push('需包含小写字母');
  if (!/\d/.test(password)) errs.push('需包含数字');
  if (!/[^A-Za-z0-9]/.test(password)) errs.push('需包含符号');

  const emailPrefix = (email || '').toLowerCase().split('@')[0] || '';
  const lower = (password || '').toLowerCase();
  if (emailPrefix && lower.includes(emailPrefix)) errs.push('不能包含邮箱前缀');
  if (username && lower.includes((username || '').toLowerCase())) errs.push('不能包含用户名');

  return errs;
}

/** Argon2 封装 */
async function hashPassword(plain) {
  return argon2.hash(plain);
}
async function verifyPassword(hash, plain) {
  return argon2.verify(hash, plain);
}

module.exports = {
  validateUsername,
  checkPasswordStrength,
  hashPassword,
  verifyPassword,
};