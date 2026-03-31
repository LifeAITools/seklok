import { Hono } from "hono";
import type { FC } from "hono/jsx";
import { getCookie, deleteCookie } from "hono/cookie";
import { getDb } from "../../db.js";
import { verifyPassword } from "../../lib/password.js";
import { createSession, setSessionCookie } from "../../middleware/session.js";
import { config } from "../../config.js";
import { Layout } from "../../views/layout.js";
import { t, type Locale, detectLocale } from "../../lib/i18n.js";

const authLogin = new Hono();

const LoginPage: FC<{ locale: Locale; error?: string; email?: string; showGoogle?: boolean }> = (props) => {
  return (
    <Layout title={t(props.locale, "auth.login.title")} locale={props.locale}>
      <h1>{t(props.locale, "auth.login.title")}</h1>
      {props.error && (
        <div class="flash error">{props.error}</div>
      )}
      <form method="post" action="/auth/login">
        <fieldset>
          <div class="form-group">
            <label for="email">{t(props.locale, "auth.login.email_label")}</label>
            <input type="text" name="email" id="email" value={props.email ?? ""} required />
          </div>
          <div class="form-group">
            <label for="password">{t(props.locale, "auth.login.password_label")}</label>
            <input type="password" name="password" id="password" required />
          </div>
          <div class="form-actions">
            <button type="submit" class="btn btn-primary">{t(props.locale, "auth.login.submit")}</button>
            <a href="/auth/register" class="btn">{t(props.locale, "auth.login.create_account")}</a>
          </div>
        </fieldset>
      </form>
      {props.showGoogle && (
        <div style="margin-top: 16px;">
          <a href="/auth/google" class="btn">{t(props.locale, "auth.login.google")}</a>
        </div>
      )}
    </Layout>
  );
};

authLogin.get("/login", (c) => {
  const locale = detectLocale(c);
  const showGoogle = !!config.googleClientId;
  return c.html(<LoginPage locale={locale} showGoogle={showGoogle} />);
});

authLogin.post("/login", async (c) => {
  const locale = detectLocale(c);
  const body = await c.req.parseBody();
  const email = String(body["email"] ?? "").trim().toLowerCase();
  const password = String(body["password"] ?? "");
  const showGoogle = !!config.googleClientId;

  const db = getDb();
  const user = db
    .query("SELECT id, password_hash FROM users WHERE email = ?")
    .get(email) as { id: string; password_hash: string | null } | null;

  if (!user || !user.password_hash) {
    return c.html(<LoginPage locale={locale} error={t(locale, "auth.login.err_invalid")} email={email} showGoogle={showGoogle} />);
  }

  const valid = await verifyPassword(password, user.password_hash);
  if (!valid) {
    return c.html(<LoginPage locale={locale} error={t(locale, "auth.login.err_invalid")} email={email} showGoogle={showGoogle} />);
  }

  const token = createSession(user.id);
  setSessionCookie(c, token);

  return c.redirect("/admin/projects");
});

authLogin.get("/logout", (c) => {
  const sessionCookie = getCookie(c, "seklok_session");
  if (sessionCookie) {
    const hasher = new Bun.CryptoHasher("sha256");
    hasher.update(sessionCookie);
    const tokenHash = hasher.digest("hex");
    const db = getDb();
    db.prepare("DELETE FROM sessions WHERE token_hash = ?").run(tokenHash);
  }
  deleteCookie(c, "seklok_session", { path: "/" });
  return c.redirect("/");
});

export default authLogin;
