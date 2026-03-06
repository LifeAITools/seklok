import nodemailer from "nodemailer";
import { config } from "../config";
import { getDb } from "../db";

const transporter = nodemailer.createTransport({
  host: config.smtpHost,
  port: config.smtpPort,
  secure: config.smtpPort === 465,
  auth: config.smtpUser ? { user: config.smtpUser, pass: config.smtpPass } : undefined,
  tls: { rejectUnauthorized: false },
});

export async function sendVerificationEmail(
  to: string,
  token: string
): Promise<void> {
  const verifyUrl = `${config.appUrl}/auth/verify?token=${token}`;

  await transporter.sendMail({
    from: `Seklok <${config.smtpFrom}>`,
    to,
    subject: "Verify your Seklok account",
    text: [
      "Click this link to verify your email address:",
      "",
      verifyUrl,
      "",
      "This link expires in 24 hours.",
      "",
      "If you did not create an account, you can safely ignore this email.",
    ].join("\n"),
  });
}

export function generateVerificationToken(userId: string): string {
  const db = getDb();
  const rawToken = crypto.randomUUID();
  const hasher = new Bun.CryptoHasher("sha256");
  hasher.update(rawToken);
  const tokenHash = hasher.digest("hex");
  const tokenId = crypto.randomUUID();
  const expiresAt = Math.floor(Date.now() / 1000) + 86400; // 24h

  db.prepare("DELETE FROM verification_tokens WHERE user_id = ?").run(userId);

  db.prepare(
    "INSERT INTO verification_tokens (id, user_id, token_hash, expires_at) VALUES (?, ?, ?, ?)"
  ).run(tokenId, userId, tokenHash, expiresAt);

  return rawToken;
}
