// src/routes/auth.js
const express = require('express');
const rateLimit = require('express-rate-limit');
const { z } = require('zod');
const argon2 = require('argon2');
const jwt = require('jsonwebtoken');

const { pool } = require('../db');
const { generate6DigitCode, hashCode } = require('../utils/otp');
const { sendVerifyEmail } = require('../utils/email');
const {
  checkPasswordStrength,
  validateUsername,
} = require('../utils/password');
const {
  signAccessToken,
  verifyToken,          // 如果你的 utils/jwt 暴露 verifyJWT，就把这一行和下面的 verifyJWT 改名保持一致
  randomToken,
  hashToken,
  setRefreshCookie,
} = require('../utils/jwt');

const router = express.Router();
const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret_key';

// 速测
router.get('/_ping', (req, res) => res.json({ ok: true }));

// ===== 限流 =====
const ipLimiter = rateLimit({
  windowMs: 60_000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
});

// 同邮箱 10 分钟最多 5 次
async function checkBusinessLimit(email) {
  const { rows } = await pool.query(
    `select count(*)::int as cnt
       from verification_codes
      where lower(email)=lower($1)
        and created_at > now() - interval '10 minutes'`,
    [email]
  );
  return rows[0].cnt < 5;
}

// ===== /request-code =====
const RequestCodeSchema = z.object({
  email: z.string().email().max(200),
  purpose: z.enum(['verify_email','reset_password']).default('verify_email'),
});

router.post('/request-code', ipLimiter, async (req, res) => {
  try {
    const { email, purpose } = RequestCodeSchema.parse(req.body);

    if (!(await checkBusinessLimit(email))) {
      return res.status(429).json({ ok:false, code:'TOO_MANY_REQUESTS', message:'Too many requests. 请稍后再试。' });
    }

    const code = generate6DigitCode();
    const codeHash = await hashCode(code);
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 分钟

    await pool.query(
      `insert into verification_codes (email, code_hash, purpose, expires_at, attempts_remaining)
       values ($1,$2,$3,$4,5)`,
      [email, codeHash, purpose, expiresAt]
    );

    await sendVerifyEmail({ to: email, code }); // DEV 模式会在控制台打印
    res.json({ ok: true });
  } catch (err) {
    if (err instanceof z.ZodError) {
      return res.status(400).json({ ok:false, code:'BAD_INPUT', errors: err.errors });
    }
    console.error('REQUEST_CODE_ERROR', err);
    res.status(500).json({ ok:false, code:'SERVER_ERROR' });
  }
});

// ===== /verify-code =====
router.post('/verify-code', ipLimiter, async (req, res) => {
  try {
    const Schema = z.object({
      email: z.string().email().max(200),
      code: z.string().regex(/^\d{6}$/),
      purpose: z.enum(['verify_email','reset_password']).default('verify_email'),
    });
    const { email, code, purpose } = Schema.parse(req.body);

    const { rows } = await pool.query(
      `select id, code_hash, expires_at, attempts_remaining, created_at
         from verification_codes
        where lower(email)=lower($1)
          and purpose=$2
          and expires_at > now()
          and attempts_remaining > 0
        order by created_at desc
        limit 1`,
      [email, purpose]
    );
    if (rows.length === 0) {
      return res.status(400).json({ ok:false, code:'CODE_NOT_FOUND_OR_EXPIRED', message:'验证码不存在或已过期。' });
    }

    const row = rows[0];
    const ok = await argon2.verify(row.code_hash, code);
    if (!ok) {
      await pool.query(
        `update verification_codes
            set attempts_remaining = attempts_remaining - 1
          where id = $1`,
        [row.id]
      );
      return res.status(400).json({ ok:false, code:'CODE_INCORRECT', message:'验证码不正确。' });
    }

    // 作废此验证码（防重放）
    await pool.query(`update verification_codes set attempts_remaining = 0 where id=$1`, [row.id]);

    // 签发一次性 registration_token（15 分钟有效）
    // 说明：历史实现有三种写法，这里源头统一可用 type:'registration'
    const token = jwt.sign(
      { type: 'registration', email }, // ✅ 统一字段
      JWT_SECRET,
      { expiresIn: '15m' }
    );

    return res.json({ ok:true, registration_token: token, expires_in_sec: 15*60 });
  } catch (err) {
    if (err instanceof z.ZodError) {
      return res.status(400).json({ ok:false, code:'BAD_INPUT', errors: err.errors });
    }
    console.error('VERIFY_CODE_ERROR', err);
    return res.status(500).json({ ok:false, code:'SERVER_ERROR' });
  }
});

// ===== /register =====
// 头部：Authorization: Bearer <registration_token>
// Body: { username, password }
router.post('/register', ipLimiter, async (req, res) => {
  try {
    // 1) 取 token
    const auth = req.headers.authorization || '';
    const m = auth.match(/^Bearer\s+(.+)$/i);
    if (!m) return res.status(401).json({ ok:false, code:'NO_REG_TOKEN', message:'缺少 registration_token。' });

    let claims;
    try {
      // 若你的 utils/jwt 暴露 verifyJWT，请替换为 verifyJWT(m[1])
      claims = verifyToken(m[1]);
    } catch {
      return res.status(401).json({ ok:false, code:'BAD_REG_TOKEN', message:'registration_token 无效或已过期。' });
    }
    if (!claims) {
      return res.status(401).json({ ok:false, code:'BAD_REG_TOKEN', message:'registration_token 无效或已过期。' });
    }

    // ✅ 兼容三种生成方式（历史兼容）：type/sub/purpose
    const isRegistration =
      claims?.type === 'registration' ||
      claims?.sub === 'registration' ||
      claims?.purpose === 'verify_email';
    if (!isRegistration || !claims.email) {
      return res.status(401).json({ ok:false, code:'BAD_REG_TOKEN', message:'registration_token 不合法。' });
    }
    const email = String(claims.email).toLowerCase();

    // 2) 校验输入
    const Schema = z.object({
      username: z.string().min(3).max(20).regex(/^[a-zA-Z0-9_]+$/, '用户名仅限字母/数字/下划线'),
      password: z.string().min(8).max(128),
    });
    const { username, password } = Schema.parse(req.body);

    if (!validateUsername(username)) {
      return res.status(400).json({ ok:false, code:'BAD_INPUT', message:'用户名需 3–20 位，仅字母/数字/下划线' });
    }
    const pwErrs = checkPasswordStrength({ password, email, username });
    if (pwErrs.length) {
      return res.status(400).json({ ok:false, code:'WEAK_PASSWORD', message:'密码强度不足', errors: pwErrs });
    }

    // 3) 重复检查
    const dupe = await pool.query(
      `select
         (exists(select 1 from users where lower(email)=lower($1))) as email_taken,
         (exists(select 1 from users where lower(username)=lower($2))) as username_taken`,
      [email, username]
    );
    if (dupe.rows[0].email_taken) {
      return res.status(409).json({ ok:false, code:'EMAIL_TAKEN', message:'该邮箱已注册' });
    }
    if (dupe.rows[0].username_taken) {
      return res.status(409).json({ ok:false, code:'USERNAME_TAKEN', message:'该用户名已被占用' });
    }

    // 4) 写库（argon2id）
    const passwordHash = await argon2.hash(password, { type: argon2.argon2id });
    const created = await pool.query(
      `insert into users (email, email_verified_at, password_hash, username)
       values ($1, now(), $2, $3)
       returning id, email, username, created_at`,
      [email, passwordHash, username]
    );
    const user = created.rows[0];

    // 5) access token
    const accessToken = signAccessToken({ sub: user.id, email: user.email, username: user.username });

    // 6) refresh token（入库哈希 & 写 HttpOnly Cookie）
    const rawRt = randomToken(32);
    const rtHash = await hashToken(rawRt);
    const ua = req.headers['user-agent'] || '';
    const ip = (req.ip || '').toString();
    const ipHash = await hashToken(ip);

    await pool.query(
      `insert into refresh_tokens (user_id, token_hash, user_agent, ip_hash, expires_at)
       values ($1,$2,$3,$4, now() + interval '30 days')`,
      [user.id, rtHash, ua, ipHash]
    );
    setRefreshCookie(res, rawRt);

    res.json({
      ok: true,
      user: { id: user.id, email: user.email, username: user.username },
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in_sec: 15 * 60,
    });
  } catch (err) {
    if (err instanceof z.ZodError) {
      return res.status(400).json({ ok:false, code:'BAD_INPUT', errors: err.errors });
    }
    console.error('REGISTER_ERROR', err);
    res.status(500).json({ ok:false, code:'SERVER_ERROR' });
  }
});

// ===== /login =====
router.post('/login', ipLimiter, async (req, res) => {
  try {
    const Schema = z.object({
      email: z.string().email().max(200),
      password: z.string().min(1),
    });
    const { email, password } = Schema.parse(req.body);
    const emailLower = email.toLowerCase();

    const { rows } = await pool.query(
      `select id, email, username, password_hash
         from users
        where lower(email) = $1
        limit 1`,
      [emailLower]
    );
    if (rows.length === 0) {
      return res.status(401).json({ ok:false, code:'INVALID_CREDENTIALS', message:'邮箱或密码不正确。' });
    }

    const user = rows[0];
    const ok = await argon2.verify(user.password_hash, password);
    if (!ok) {
      return res.status(401).json({ ok:false, code:'INVALID_CREDENTIALS', message:'邮箱或密码不正确。' });
    }

    pool.query(`update users set last_login_at = now() where id = $1`, [user.id]).catch(()=>{});

    const accessToken = signAccessToken({ sub: user.id, email: user.email, username: user.username });

    const rawRt = randomToken(32);
    const rtHash = await hashToken(rawRt);
    const ua = req.headers['user-agent'] || '';
    const ip = (req.ip || '').toString();
    const ipHash = await hashToken(ip);

    await pool.query(
      `insert into refresh_tokens (user_id, token_hash, user_agent, ip_hash, expires_at)
       values ($1,$2,$3,$4, now() + interval '30 days')`,
      [user.id, rtHash, ua, ipHash]
    );
    setRefreshCookie(res, rawRt);

    res.json({
      ok: true,
      user: { id: user.id, email: user.email, username: user.username },
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in_sec: 15 * 60,
    });
  } catch (err) {
    if (err instanceof z.ZodError) {
      return res.status(400).json({ ok:false, code:'BAD_INPUT', errors: err.errors });
    }
    console.error('LOGIN_ERROR', err);
    res.status(500).json({ ok:false, code:'SERVER_ERROR' });
  }
});

// ===== /refresh =====
router.post('/refresh', ipLimiter, async (req, res) => {
  try {
    const rawRt = (req.cookies && req.cookies.rt) || '';
    if (!rawRt) return res.status(401).json({ ok:false, code:'NO_REFRESH', message:'缺少刷新令牌。' });

    const rtHash = await hashToken(rawRt);
    const { rows } = await pool.query(
      `select user_id, expires_at
         from refresh_tokens
        where token_hash = $1
          and expires_at > now()
        limit 1`,
      [rtHash]
    );
    if (rows.length === 0) {
      return res.status(401).json({ ok:false, code:'BAD_REFRESH', message:'刷新令牌无效或已过期。' });
    }

    const userId = rows[0].user_id;
    const u = await pool.query(
      `select id, email, username from users where id = $1 limit 1`,
      [userId]
    );
    if (u.rows.length === 0) {
      return res.status(401).json({ ok:false, code:'USER_GONE', message:'用户不存在。' });
    }
    const user = u.rows[0];

    // 旋转 refresh token（安全做法）：生成新 token，入库并删除旧 token
    const newRt = randomToken(32);
    const newRtHash = await hashToken(newRt);
    const ua = req.headers['user-agent'] || '';
    const ip = (req.ip || '').toString();
    const ipHash = await hashToken(ip);

    await pool.query('BEGIN');
    await pool.query(
      `insert into refresh_tokens (user_id, token_hash, user_agent, ip_hash, expires_at)
       values ($1,$2,$3,$4, now() + interval '30 days')`,
      [user.id, newRtHash, ua, ipHash]
    );
    await pool.query(`delete from refresh_tokens where token_hash = $1`, [rtHash]);
    await pool.query('COMMIT');

    setRefreshCookie(res, newRt);
    const accessToken = signAccessToken({ sub: user.id, email: user.email, username: user.username });

    res.json({ ok:true, user, access_token: accessToken, token_type:'Bearer', expires_in_sec: 15*60 });
  } catch (err) {
    await pool.query('ROLLBACK').catch(()=>{});
    console.error('REFRESH_ERROR', err);
    res.status(500).json({ ok:false, code:'SERVER_ERROR' });
  }
});

// ===== /logout =====
router.post('/logout', ipLimiter, async (req, res) => {
  try {
    const rawRt = (req.cookies && req.cookies.rt) || '';
    if (rawRt) {
      const rtHash = await hashToken(rawRt);
      await pool.query(`delete from refresh_tokens where token_hash = $1`, [rtHash]).catch(()=>{});
    }
    // 清理 Cookie（若 setRefreshCookie 使用的 path/sameSite/secure 不同，请保持一致选项）
    res.clearCookie('rt', { httpOnly: true, sameSite: 'lax', path: '/' });
    res.json({ ok:true });
  } catch (err) {
    console.error('LOGOUT_ERROR', err);
    res.status(500).json({ ok:false, code:'SERVER_ERROR' });
  }
});

// ===== /me =====
router.get('/me', async (req, res) => {
  try {
    const auth = req.headers.authorization || '';
    const m = auth.match(/^Bearer\s+(.+)$/i);
    if (!m) return res.status(401).json({ ok:false, code:'NO_ACCESS_TOKEN' });

    let claims;
    try {
      // 若你的 utils/jwt 暴露 verifyJWT，请替换为 verifyJWT(m[1])
      claims = verifyToken(m[1]);
    } catch {
      return res.status(401).json({ ok:false, code:'BAD_ACCESS_TOKEN' });
    }
    if (!claims || !claims.sub) {
      return res.status(401).json({ ok:false, code:'BAD_ACCESS_TOKEN' });
    }

    const { rows } = await pool.query(
      `select id, email, username from users where id = $1 limit 1`,
      [claims.sub]
    );
    if (rows.length === 0) {
      return res.status(404).json({ ok:false, code:'USER_NOT_FOUND' });
    }
    res.json({ ok:true, user: rows[0] });
  } catch (err) {
    console.error('ME_ERROR', err);
    res.status(500).json({ ok:false, code:'SERVER_ERROR' });
  }
});

module.exports = router;