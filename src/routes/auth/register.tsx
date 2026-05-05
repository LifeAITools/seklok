import { Hono } from "hono";
import type { FC } from "hono/jsx";
import { getDb } from "../../db.js";
import { hashPassword } from "../../lib/password.js";
import { createSession, setSessionCookie } from "../../middleware/session.js";
import { generateVerificationToken, sendVerificationEmail } from "../../lib/email.js";
import { generateKeyB64 } from "../../lib/encryption.js";
import { setMasterKey } from "../../lib/master-keys.js";
import { Layout } from "../../views/layout.js";
import { SecretRevealPage } from "../../views/secret-reveal.js";
import { config } from "../../config.js";
import { t, type Locale, detectLocale } from "../../lib/i18n.js";

const authRegister = new Hono();

const RegisterPage: FC<{ locale: Locale; error?: string; email?: string; name?: string }> = (props) => {
  return (
    <Layout title={t(props.locale, "auth.register.title")} locale={props.locale}>
      <h1>{t(props.locale, "auth.register.title")}</h1>
      {props.error && (
        <div class="flash error">{props.error}</div>
      )}
      <form method="post" action="/auth/register">
        <fieldset>
          <div class="form-group">
            <label for="name">{t(props.locale, "auth.register.name_label")}</label>
            <input type="text" name="name" id="name" value={props.name ?? ""} required />
          </div>
          <div class="form-group">
            <label for="email">{t(props.locale, "auth.register.email_label")}</label>
            <input type="text" name="email" id="email" value={props.email ?? ""} required />
          </div>
          <div class="form-group">
            <label for="password">{t(props.locale, "auth.register.password_label")}</label>
            <input type="password" name="password" id="password" required />
          </div>
          <div class="form-actions">
            <button type="submit" class="btn btn-primary">{t(props.locale, "auth.register.submit")}</button>
            <a href="/auth/login" class="btn">{t(props.locale, "auth.register.has_account")}</a>
          </div>
        </fieldset>
      </form>
    </Layout>
  );
};

authRegister.get("/register", (c) => {
  const locale = detectLocale(c);
  return c.html(<RegisterPage locale={locale} />);
});

authRegister.post("/register", async (c) => {
  const locale = detectLocale(c);
  const body = await c.req.parseBody();
  const email = String(body["email"] ?? "").trim().toLowerCase();
  const password = String(body["password"] ?? "");
  const name = String(body["name"] ?? "").trim();

  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return c.html(<RegisterPage locale={locale} error={t(locale, "auth.register.err_email")} email={email} name={name} />);
  }

  if (password.length < 8) {
    return c.html(<RegisterPage locale={locale} error={t(locale, "auth.register.err_password")} email={email} name={name} />);
  }

  if (!name) {
    return c.html(<RegisterPage locale={locale} error={t(locale, "auth.register.err_name")} email={email} name={name} />);
  }

  const db = getDb();

  const existing = db
    .query("SELECT id FROM users WHERE email = ?")
    .get(email) as { id: string } | null;

  if (existing) {
    return c.html(<RegisterPage locale={locale} error={t(locale, "auth.register.err_duplicate")} email={email} name={name} />);
  }

  const userId = crypto.randomUUID();
  const passwordHash = await hashPassword(password);

  db.prepare(
    "INSERT INTO users (id, email, password_hash, name, role, email_verified) VALUES (?, ?, ?, ?, 'user', 0)"
  ).run(userId, email, passwordHash, name);

  // Auto-verify if SMTP not configured
  if (!config.smtpUser) {
    db.prepare("UPDATE users SET email_verified = 1 WHERE id = ?").run(userId);
  }

  const defaultProjectName = t(locale, "default_project");
  db.prepare(
    "INSERT INTO projects (name, description, owner_id) VALUES (?, '', ?)"
  ).run(defaultProjectName, userId);

  const newProject = db.query("SELECT id FROM projects WHERE owner_id = ? AND name = ?").get(userId, defaultProjectName) as { id: number };
  const masterKey = generateKeyB64();
  setMasterKey(newProject.id, masterKey);
  const hasher = new Bun.CryptoHasher("sha256");
  hasher.update(masterKey);
  db.prepare("UPDATE projects SET master_key_hash = ? WHERE id = ?").run(hasher.digest("hex"), newProject.id);

  // Send verification email (non-blocking — don't fail registration if email fails)
  try {
    const verifyToken = generateVerificationToken(userId);
    await sendVerificationEmail(email, verifyToken);
  } catch (err) {
    console.error("[seklok] Failed to send verification email:", err);
  }

  const token = createSession(userId);
  setSessionCookie(c, token);

  // Render master key directly — never via redirect URL. See bug 9c497016 / d664fbf2.
  return c.html(
    <SecretRevealPage
      locale={locale}
      title={t(locale, "secret_reveal.master_key_title", { name: defaultProjectName })}
      description={t(locale, "secret_reveal.master_key_description")}
      warning={t(locale, "secret_reveal.master_key_warning")}
      secret={masterKey}
      downloadFilename={`seklok-master-key-${defaultProjectName.replace(/[^a-zA-Z0-9-_]/g, "_")}`}
      continueUrl={`/admin/projects/${newProject.id}`}
    />
  );
});

export default authRegister;
