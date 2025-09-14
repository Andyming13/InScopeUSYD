const crypto = require('crypto');
const argon2 = require('argon2');

function generate6DigitCode() {
  const n = crypto.randomInt(0, 1000000);
  return n.toString().padStart(6, '0');
}
async function hashCode(code) {
  return argon2.hash(code, { type: argon2.argon2id });
}
module.exports = { generate6DigitCode, hashCode };