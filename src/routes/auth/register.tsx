import { Hono } from "hono";
import type { FC } from "hono/jsx";
import { getDb } from "../../db.js";
import { hashPassword } from "../../lib/password.js";
import { createSession, setSessionCookie } from "../../middleware/session.js";
import { generateVerificationToken, sendVerificationEmail } from "../../lib/email.js";
import { Layout } from "../../views/layout.js";

const authRegister = new Hono();

const RegisterPage: FC<{ error?: string; email?: string; name?: string }> = (props) => {
  return (
    <Layout title="Register">
      <h1>Create Account</h1>
      {props.error && (
        <div class="flash error">{props.error}</div>
      )}
      <form method="post" action="/auth/register">
        <fieldset>
          <div class="form-group">
            <label for="name">Name *</label>
            <input type="text" name="name" id="name" value={props.name ?? ""} required />
          </div>
          <div class="form-group">
            <label for="email">Email *</label>
            <input type="text" name="email" id="email" value={props.email ?? ""} required />
          </div>
          <div class="form-group">
            <label for="password">Password *</label>
            <input type="password" name="password" id="password" required />
          </div>
          <div class="form-actions">
            <button type="submit" class="btn btn-primary">Register</button>
            <a href="/auth/login" class="btn">Already have an account?</a>
          </div>
        </fieldset>
      </form>
    </Layout>
  );
};

authRegister.get("/register", (c) => {
  return c.html(<RegisterPage />);
});

authRegister.post("/register", async (c) => {
  const body = await c.req.parseBody();
  const email = String(body["email"] ?? "").trim().toLowerCase();
  const password = String(body["password"] ?? "");
  const name = String(body["name"] ?? "").trim();

  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return c.html(<RegisterPage error="Invalid email format" email={email} name={name} />);
  }

  if (password.length < 8) {
    return c.html(<RegisterPage error="Password must be at least 8 characters" email={email} name={name} />);
  }

  if (!name) {
    return c.html(<RegisterPage error="Name is required" email={email} name={name} />);
  }

  const db = getDb();

  const existing = db
    .query("SELECT id FROM users WHERE email = ?")
    .get(email) as { id: string } | null;

  if (existing) {
    return c.html(<RegisterPage error="An account with this email already exists" email={email} name={name} />);
  }

  const userId = crypto.randomUUID();
  const passwordHash = await hashPassword(password);

  db.prepare(
    "INSERT INTO users (id, email, password_hash, name, role, email_verified) VALUES (?, ?, ?, ?, 'user', 0)"
  ).run(userId, email, passwordHash, name);

  db.prepare(
    "INSERT INTO projects (name, description, owner_id) VALUES (?, '', ?)"
  ).run("My Secrets", userId);

  // Send verification email (non-blocking — don't fail registration if email fails)
  try {
    const verifyToken = generateVerificationToken(userId);
    await sendVerificationEmail(email, verifyToken);
  } catch (err) {
    console.error("[seklok] Failed to send verification email:", err);
  }

  const token = createSession(userId);
  setSessionCookie(c, token);

  return c.redirect("/admin");
});

export default authRegister;
