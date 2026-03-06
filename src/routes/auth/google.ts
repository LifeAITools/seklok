import { Hono } from "hono";
import { getCookie, setCookie } from "hono/cookie";
import { getDb } from "../../db.js";
import { config } from "../../config.js";
import { createSession, setSessionCookie } from "../../middleware/session.js";

const authGoogle = new Hono();

authGoogle.get("/google", (c) => {
  if (!config.googleClientId) {
    return c.notFound();
  }

  const state = crypto.randomUUID();
  setCookie(c, "oauth_state", state, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "Lax",
    maxAge: 600,
    path: "/",
  });

  const params = new URLSearchParams({
    client_id: config.googleClientId,
    redirect_uri: config.googleRedirectUri,
    response_type: "code",
    scope: "openid email profile",
    state,
  });

  return c.redirect(`https://accounts.google.com/o/oauth2/v2/auth?${params.toString()}`);
});

authGoogle.get("/google/callback", async (c) => {
  if (!config.googleClientId) {
    return c.notFound();
  }

  const stateParam = c.req.query("state");
  const stateCookie = getCookie(c, "oauth_state");

  if (!stateParam || !stateCookie || stateParam !== stateCookie) {
    return c.text("Invalid OAuth state", 400);
  }

  const code = c.req.query("code");
  if (!code) {
    return c.text("Missing authorization code", 400);
  }

  const tokenRes = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      code,
      client_id: config.googleClientId,
      client_secret: config.googleClientSecret,
      redirect_uri: config.googleRedirectUri,
      grant_type: "authorization_code",
    }),
  });

  if (!tokenRes.ok) {
    return c.text("Failed to exchange authorization code", 400);
  }

  const tokenData = (await tokenRes.json()) as { id_token?: string };
  if (!tokenData.id_token) {
    return c.text("No id_token in response", 400);
  }

  const payload = JSON.parse(atob(tokenData.id_token.split(".")[1])) as {
    email: string;
    name?: string;
    sub: string;
  };
  const { email, name, sub: googleId } = payload;

  const db = getDb();

  let user = db
    .query("SELECT id, google_id FROM users WHERE google_id = ?")
    .get(googleId) as { id: string; google_id: string | null } | null;

  if (!user) {
    user = db
      .query("SELECT id, google_id FROM users WHERE email = ?")
      .get(email) as { id: string; google_id: string | null } | null;

    if (user) {
      if (!user.google_id) {
        db.prepare("UPDATE users SET google_id = ? WHERE id = ?").run(googleId, user.id);
      }
    } else {
      const userId = crypto.randomUUID();
      db.prepare(
        "INSERT INTO users (id, email, password_hash, name, google_id, role, email_verified) VALUES (?, ?, NULL, ?, ?, 'user', 1)"
      ).run(userId, email, name ?? email, googleId);

      db.prepare(
        "INSERT INTO projects (name, description, owner_id) VALUES (?, '', ?)"
      ).run("My Secrets", userId);

      user = { id: userId, google_id: googleId };
    }
  }

  const token = createSession(user.id);
  setSessionCookie(c, token);

  return c.redirect("/admin");
});

export default authGoogle;
