import { Hono } from "hono";
import { cors } from "hono/cors";

const app = new Hono();

app.use("/*", cors({
  origin: ["https://seklok.com", "https://www.seklok.com"],
  allowMethods: ["POST", "OPTIONS"],
}));

app.get("/health", (c) => c.json({ status: "ok" }));

app.post("/api/waitlist", async (c) => {
  const body = await c.req.json().catch(() => null);
  if (!body?.email || typeof body.email !== "string") {
    return c.json({ error: "Email is required" }, 400);
  }

  const email = body.email.trim().toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return c.json({ error: "Invalid email format" }, 400);
  }

  try {
    await sendEmail(email);
    console.log(`[waitlist] ${email} at ${new Date().toISOString()}`);
    return c.json({ success: true, message: "You're on the waitlist!" });
  } catch (err) {
    console.error(`[waitlist] SMTP error for ${email}:`, err);
    return c.json({ error: "Failed to process. Try again later." }, 500);
  }
});

async function sendEmail(subscriberEmail: string) {
  const net = require("net");

  const lines: string[] = [];
  const sock = net.createConnection(587, "smtp.muid.io");

  const send = (cmd: string): Promise<string> =>
    new Promise((resolve, reject) => {
      const timeout = setTimeout(() => reject(new Error("SMTP timeout")), 10000);
      sock.once("data", (data: Buffer) => {
        clearTimeout(timeout);
        const resp = data.toString();
        if (resp.startsWith("4") || resp.startsWith("5")) {
          reject(new Error(`SMTP error: ${resp.trim()}`));
        } else {
          resolve(resp.trim());
        }
      });
      if (cmd) sock.write(cmd + "\r\n");
    });

  await new Promise<void>((resolve, reject) => {
    sock.once("data", () => resolve());
    sock.once("error", reject);
  });

  await send("EHLO seklok.com");
  await send("MAIL FROM:<noreply@kiberos.ai>");
  await send(`RCPT TO:<relishev@gmail.com>`);
  await send("DATA");

  const date = new Date().toUTCString();
  const message = [
    `From: Seklok Waitlist <noreply@kiberos.ai>`,
    `Reply-To: waitlist@seklok.com`,
    `To: relishev@gmail.com`,
    `Subject: Seklok Cloud Waitlist: ${subscriberEmail}`,
    `Date: ${date}`,
    `Content-Type: text/plain; charset=utf-8`,
    ``,
    `New waitlist signup for Seklok Cloud:`,
    ``,
    `Email: ${subscriberEmail}`,
    `Time: ${date}`,
    `Source: seklok.com waitlist form`,
  ].join("\r\n");

  await send(message + "\r\n.");
  await send("QUIT");
  sock.destroy();
}

export default {
  port: 8099,
  fetch: app.fetch,
};
