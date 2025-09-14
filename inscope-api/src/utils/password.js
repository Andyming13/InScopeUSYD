// src/utils/password.js
function checkPasswordStrength(pw, { email = '', username = '' } = {}) {
    const problems = [];
    if (pw.length < 8) problems.push('长度至少 8 位');
    if (!/[a-z]/.test(pw)) problems.push('需要小写字母');
    if (!/[A-Z]/.test(pw)) problems.push('需要大写字母');
    if (!/[0-9]/.test(pw)) problems.push('需要数字');
    if (!/[^A-Za-z0-9]/.test(pw)) problems.push('需要符号');
    const low = pw.toLowerCase();
    if (email && email.split('@')[0] && low.includes(email.split('@')[0].toLowerCase())) {
      problems.push('密码不应包含邮箱前缀');
    }
    if (username && low.includes(username.toLowerCase())) {
      problems.push('密码不应包含用户名');
    }
    return { ok: problems.length === 0, problems };
  }
  
  module.exports = { checkPasswordStrength };