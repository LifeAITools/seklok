import type { FC } from "hono/jsx";
import { Layout } from "./layout.js";
import { t, type Locale } from "../lib/i18n.js";

export const HomePage: FC<{ locale: Locale }> = (props) => {
  return (
    <Layout title={t(props.locale, "home.welcome")} locale={props.locale}>
      <h1>{t(props.locale, "home.welcome")}</h1>
      <p style="margin-top: 12px;">
        <a href="/admin/projects" class="btn btn-primary">{t(props.locale, "home.go_to_projects")}</a>
        <a href="/auth/login" class="btn" style="margin-left: 8px;">{t(props.locale, "home.sign_in")}</a>
        <a href="/auth/register" class="btn" style="margin-left: 8px;">{t(props.locale, "home.create_account")}</a>
      </p>
    </Layout>
  );
};
