import type { MiddlewareHandler } from "hono";
import { config } from "../config";

export const basicAuth: MiddlewareHandler = async (c, next) => {
  if (!config.adminUser) {
    return next();
  }

  const authHeader = c.req.header("Authorization");
  if (!authHeader || !authHeader.startsWith("Basic ")) {
    return c.newResponse("Unauthorized", 401, {
      "WWW-Authenticate": 'Basic realm="Login Required"',
    });
  }

  const decoded = Buffer.from(authHeader.slice(6), "base64").toString("utf-8");
  const sepIdx = decoded.indexOf(":");
  if (sepIdx === -1) {
    return c.newResponse("Unauthorized", 401, {
      "WWW-Authenticate": 'Basic realm="Login Required"',
    });
  }

  const username = decoded.slice(0, sepIdx);
  const password = decoded.slice(sepIdx + 1);

  if (username !== config.adminUser || password !== config.adminPass) {
    return c.newResponse("Unauthorized", 401, {
      "WWW-Authenticate": 'Basic realm="Login Required"',
    });
  }

  return next();
};
