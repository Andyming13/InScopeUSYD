const mode = (process.env.EMAIL_MODE || 'log').toLowerCase();

async function sendVerifyEmail({ to, code }) {
  if (mode === 'log') {
    console.log(`[DEV MAIL] to=${to} code=${code}`); // 本地调试直接看日志
    return;
  }
  if (mode === 'resend') {
    const { Resend } = require('resend');
    const resend = new Resend(process.env.RESEND_API_KEY);
    const from = process.env.EMAIL_FROM || 'InScope <onboarding@resend.dev>';
    const subject = 'Your InScope verification code | InScope 验证码';
    const html = `
      <div style="font-family:system-ui,Segoe UI,Roboto,Helvetica,Arial">
        <p>Hi there,</p>
        <p>Your verification code is:</p>
        <div style="font-size:28px;font-weight:800;letter-spacing:4px">${code}</div>
        <p>This code expires in <b>10 minutes</b>.</p>
        <hr/>
        <p>您好！</p>
        <p>您的验证码为：</p>
        <div style="font-size:28px;font-weight:800;letter-spacing:4px">${code}</div>
        <p>该验证码 <b>10 分钟内有效</b>。</p>
      </div>`;
    await resend.emails.send({ from, to, subject, html });
    return;
  }
  throw new Error(`Unsupported EMAIL_MODE=${mode}`);
}

module.exports = { sendVerifyEmail };