import type { MiddlewareHandler } from "hono";
import { rightsInclude, type Right } from "../lib/service-tokens";

export function requireRight(...required: Right[]): MiddlewareHandler {
  return async (c, next) => {
    const auth = c.get("auth");
    if (!auth) {
      return c.json({ error: "Unauthorized", message: "Not authenticated" }, 401);
    }

    for (const right of required) {
      if (!rightsInclude(auth.rights, right)) {
        return c.json(
          { error: "Forbidden", message: `Insufficient rights. Required: ${right}` },
          403
        );
      }
    }

    return next();
  };
}
