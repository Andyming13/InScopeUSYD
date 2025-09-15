// src/utils/email.js
const MODE = (process.env.EMAIL_MODE || 'log').toLowerCase();
const FROM = process.env.EMAIL_FROM || 'InScope <onboarding@resend.dev>';
const RESEND_KEY = process.env.RESEND_API_KEY;

async function sendViaResend({ to, subject, html }) {
  if (!RESEND_KEY) throw new Error('RESEND_API_KEY missing');
  // Node 18+ 自带 fetch
  const res = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${RESEND_KEY}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ from: FROM, to, subject, html })
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const msg = data?.message || data?.error || `HTTP ${res.status}`;
    throw new Error(`Resend error: ${msg}`);
  }
  return data;
}

// 发送验证码邮件
async function sendVerifyEmail({ to, code }) {
  const subject = 'Your InScope verification code';
  const html = `
    <div style="font-family:system-ui,Segoe UI,Arial,sans-serif">
      <p>Hi there,</p>
      <p>Your verification code is:</p>
      <p style="font-size:28px;font-weight:700;letter-spacing:3px">${code}</p>
      <p>This code expires in 10 minutes.</p>
      <hr/>
      <p>InScope – Bilingual Exchange @ USYD</p>
    </div>
  `;

  if (MODE === 'resend') {
    return sendViaResend({ to, subject, html });
  }

  // 默认 log 模式
  console.log(`[DEV MAIL] to=${to} code=${code}`);
  return { ok: true, dev: true };
}

module.exports = { sendVerifyEmail };