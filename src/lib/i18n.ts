import type { Context } from "hono";
import { getCookie } from "hono/cookie";

import en from "../../locales/en.json";
import ru from "../../locales/ru.json";

const locales: Record<string, Record<string, string>> = { en, ru };
const defaultLocale = "en";
const supportedLocales = Object.keys(locales);

export type Locale = "en" | "ru";

export function detectLocale(c: Context): Locale {
  const cookie = getCookie(c, "seklok_lang");
  if (cookie && supportedLocales.includes(cookie)) return cookie as Locale;

  const accept = c.req.header("Accept-Language") ?? "";
  for (const part of accept.split(",")) {
    const lang = part.split(";")[0].trim().slice(0, 2).toLowerCase();
    if (supportedLocales.includes(lang)) return lang as Locale;
  }

  return defaultLocale as Locale;
}

export function t(locale: Locale, key: string, params?: Record<string, string | number>): string {
  let text = locales[locale]?.[key] ?? locales[defaultLocale]?.[key] ?? key;

  if (params) {
    for (const [k, v] of Object.entries(params)) {
      text = text.replace(new RegExp(`\\{${k}\\}`, "g"), String(v));
    }
  }

  return text;
}

export function getSupportedLocales(): string[] {
  return supportedLocales;
}
