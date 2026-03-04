import type { MiddlewareHandler } from "hono";
import { verifyServiceToken, parseRights, type Right } from "../lib/service-tokens";

declare module "hono" {
  interface ContextVariableMap {
    auth: {
      projectId: number;
      environmentId: number;
      rights: Right[];
      masterKey: string;
    };
  }
}

export const serviceTokenAuth: MiddlewareHandler = async (c, next) => {
  const authHeader = c.req.header("Authorization");
  if (!authHeader) {
    return c.json({ error: "Unauthorized", message: "Missing Authorization header" }, 401);
  }

  let token = authHeader;
  if (token.startsWith("Bearer ")) {
    token = token.slice(7);
  }

  try {
    const { masterKey, tokenRecord } = verifyServiceToken(token);
    c.set("auth", {
      projectId: tokenRecord.project_id,
      environmentId: tokenRecord.environment_id,
      rights: parseRights(tokenRecord.rights),
      masterKey,
    });
    return next();
  } catch {
    return c.json(
      { error: "Unauthorized", message: "Invalid or expired service token" },
      401
    );
  }
};
