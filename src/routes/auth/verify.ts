import { Hono } from "hono";
import { getDb } from "../../db.js";
import { requireAuth, type AuthUser } from "../../middleware/session.js";
import {
  sendVerificationEmail,
  generateVerificationToken,
} from "../../lib/email.js";

const app = new Hono();

// GET /auth/verify?token=X — verify email
app.get("/verify", async (c) => {
  const token = c.req.query("token");
  if (!token) {
    return c.html(errorPage("Missing verification token"), 400);
  }

  const hasher = new Bun.CryptoHasher("sha256");
  hasher.update(token);
  const tokenHash = hasher.digest("hex");

  const db = getDb();
  const now = Math.floor(Date.now() / 1000);

  const row = db
    .query<{ id: string; user_id: string }, [string, number]>(
      "SELECT id, user_id FROM verification_tokens WHERE token_hash = ? AND expires_at > ?"
    )
    .get(tokenHash, now);

  if (!row) {
    return c.html(errorPage("Invalid or expired verification link"), 400);
  }

  db.prepare("UPDATE users SET email_verified = 1, updated_at = datetime('now') WHERE id = ?").run(
    row.user_id
  );
  db.prepare("DELETE FROM verification_tokens WHERE id = ?").run(row.id);

  return c.redirect("/auth/login?verified=1");
});

// POST /auth/resend-verification — resend verification email
app.post("/resend-verification", requireAuth, async (c) => {
  const user = c.get("user") as AuthUser;

  if (user.emailVerified) {
    return c.redirect("/admin/projects?flash_type=info&flash_msg=" + encodeURIComponent("Email already verified"));
  }

  try {
    const rawToken = generateVerificationToken(user.id);
    await sendVerificationEmail(user.email, rawToken);
  } catch (err) {
    console.error("[seklok] Failed to send verification email:", err);
    return c.redirect("/admin/projects?flash_type=error&flash_msg=" + encodeURIComponent("Failed to send verification email. Try again later."));
  }

  return c.redirect("/admin/projects?flash_type=success&flash_msg=" + encodeURIComponent("Verification email sent. Check your inbox."));
});

function errorPage(message: string): string {
  return `<!DOCTYPE html>
<html>
<head><title>Verification Error</title></head>
<body>
<h1>Email Verification</h1>
<p>${message}</p>
<p><a href="/auth/login">Go to login</a></p>
</body>
</html>`;
}

export default app;
