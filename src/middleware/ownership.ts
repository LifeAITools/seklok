import { createMiddleware } from "hono/factory";
import { getDb } from "../db";
import type { AuthUser } from "./session";

declare module "hono" {
  interface ContextVariableMap {
    user: AuthUser;
  }
}

export function requireOwnerOrAdmin(paramName = "id") {
  return createMiddleware(async (c, next) => {
    const user = c.get("user") as AuthUser | undefined;
    if (!user) return c.text("Unauthorized", 401);
    if (user.role === "admin") return next();

    const projectId = c.req.param(paramName);
    if (!projectId) return c.text("Bad request", 400);
    const db = getDb();
    const project = db
      .query("SELECT owner_id FROM projects WHERE id = ?")
      .get(projectId) as { owner_id: string | null } | null;

    if (!project) return c.text("Not found", 404);
    if (project.owner_id !== user.id) return c.text("Forbidden", 403);

    return next();
  });
}

export function getProjectFilter(user: {
  id: string;
  role: string;
}): { clause: string; params: string[] } {
  if (user.role === "admin") {
    return { clause: "", params: [] };
  }
  return { clause: "AND owner_id = ?", params: [user.id] };
}
