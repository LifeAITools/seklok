import type { FC } from "hono/jsx";
import { Layout } from "./layout.js";

export const HomePage: FC = () => {
  return (
    <Layout title="Home">
      <h1>Welcome to Seklok</h1>
      <p style="margin-top: 12px;">
        <a href="/admin/projects" class="btn btn-primary">Go to projects</a>
      </p>
    </Layout>
  );
};
