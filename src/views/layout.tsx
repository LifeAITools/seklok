import type { FC, PropsWithChildren } from "hono/jsx";
import { raw } from "hono/html";
import { t, type Locale, getSupportedLocales } from "../lib/i18n.js";

interface LayoutProps {
  title: string;
  locale?: Locale;
  flash?: { type: string; message: string };
  projectId?: number;
  projectName?: string;
}

export const Layout: FC<PropsWithChildren<LayoutProps>> = (props) => {
  const locale = props.locale ?? "en";
  return (
    <html>
      <head>
        <meta charset="utf-8" />
        <title>{props.title} - {t(locale, "site.name")}</title>
        {raw(`<style>
          * { box-sizing: border-box; margin: 0; padding: 0; }
          body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; color: #333; background: #f7f7f7; padding: 0; }
          a { color: #0078e7; text-decoration: none; }
          a:hover { text-decoration: underline; }
          nav { background: #333; color: #fff; padding: 10px 20px; display: flex; gap: 8px; align-items: center; }
          nav a { color: #fff; font-weight: bold; }
          nav span { color: #aaa; }
          .container { max-width: 960px; margin: 20px auto; padding: 0 20px; }
          .flash { padding: 10px 16px; margin-bottom: 16px; border-radius: 4px; }
          .flash.success { background: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
          .flash.error { background: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
          table { width: 100%; border-collapse: collapse; background: #fff; margin-top: 12px; }
          th, td { padding: 8px 12px; border: 1px solid #ddd; text-align: left; }
          th { background: #f0f0f0; font-weight: 600; }
          tr:hover { background: #fafafa; }
          .btn { display: inline-block; padding: 6px 14px; border: 1px solid #ccc; border-radius: 4px; background: #fff; color: #333; cursor: pointer; font-size: 14px; text-decoration: none; }
          .btn:hover { background: #e8e8e8; text-decoration: none; }
          .btn-primary { background: #0078e7; color: #fff; border-color: #0078e7; }
          .btn-primary:hover { background: #0063c1; }
          .btn-danger { background: #dc3545; color: #fff; border-color: #dc3545; }
          .btn-danger:hover { background: #c82333; }
          .btn-sm { padding: 3px 8px; font-size: 12px; }
          form fieldset { border: 1px solid #ddd; padding: 16px; border-radius: 4px; background: #fff; }
          form legend { font-weight: 600; padding: 0 6px; }
          label { display: inline-block; min-width: 180px; margin-bottom: 4px; font-weight: 500; }
          input[type="text"], input[type="password"], textarea, select { padding: 6px 10px; border: 1px solid #ccc; border-radius: 4px; font-size: 14px; width: 350px; }
          textarea { vertical-align: top; }
          .form-group { margin-bottom: 12px; }
          .form-actions { margin-top: 16px; }
          .inline-actions { display: flex; gap: 6px; }
          h1 { margin: 16px 0; }
          h3 { margin: 12px 0 8px; }
          .warning { background: #fff3cd; color: #856404; border: 1px solid #ffeeba; padding: 12px; border-radius: 4px; margin-bottom: 12px; }
          .master-key-display { margin: 12px 0; }
          .master-key-display input { width: 400px; font-family: monospace; }
          .env-grid { display: flex; gap: 20px; flex-wrap: wrap; margin-top: 12px; }
          .env-card { background: #fff; border: 1px solid #ddd; border-radius: 4px; padding: 16px; min-width: 200px; }
          hr { margin: 16px 0; border: none; border-top: 1px solid #ddd; }
          .secret-row { display: flex; gap: 8px; margin-bottom: 8px; align-items: start; }
          .secret-row input[type="text"], .secret-row textarea { width: auto; flex: 1; }
          .secret-row .name-col { width: 200px; min-width: 200px; }
          .secret-row .value-col { flex: 1; }
          .secret-row .actions-col { min-width: 120px; display: flex; gap: 4px; }
          .controls { margin-bottom: 12px; display: flex; gap: 8px; }
          .copyable { font-family: monospace; background: #f5f5f5; padding: 8px; border: 1px solid #ddd; border-radius: 4px; display: flex; gap: 8px; align-items: center; margin: 8px 0; }
          .copyable input { flex: 1; font-family: monospace; border: none; background: transparent; font-size: 14px; }
        </style>`)}
        {raw(`<script>
          function copyToClipboard(inputId) {
            var input = document.getElementById(inputId);
            if (!input) return;
            input.type = 'text';
            input.select();
            document.execCommand('copy');
            input.type = 'password';
          }

          var _newSecretIdx = 0;

          function addSecretRow(name, value) {
            var idx = _newSecretIdx++;
            var container = document.getElementById('secrets-container');
            if (!container) return;
            var row = document.createElement('div');
            row.className = 'secret-row';
            row.id = 'secret-row-new-' + idx;
            row.innerHTML =
              '<div class="name-col">' +
              '<input type="text" name="secrets[new-' + idx + '][name]" value="' + (name || '') + '" placeholder="SECRET_NAME" required />' +
              '</div>' +
              '<div class="value-col">' +
              '<input type="text" name="secrets[new-' + idx + '][value]" value="' + (value || '') + '" placeholder="value" />' +
              '</div>' +
              '<div class="actions-col">' +
              '<button type="button" class="btn btn-sm btn-danger" onclick="removeSecretRow(\\\'new-' + idx + '\\\')">Delete</button>' +
              '</div>';
            container.appendChild(row);
          }

          function removeSecretRow(id) {
            var row = document.getElementById('secret-row-' + id);
            if (row) row.remove();
            var del = document.getElementById('deleted-ids');
            if (del && !id.toString().startsWith('new')) {
              del.value = del.value ? del.value + ',' + id : id;
            }
          }
        </script>`)}
      </head>
      <body>
        <nav>
          <a href="/admin">{t(locale, "site.name")}</a>
          <span>/</span>
          <a href="/admin/projects">{t(locale, "nav.projects")}</a>
          {props.projectId && (
            <>
              <span>/</span>
              <a href={`/admin/projects/${props.projectId}`}>{props.projectName ?? `#${props.projectId}`}</a>
            </>
          )}
          <span style="margin-left: auto;">
            <a href="/auth/logout">{t(locale, "nav.logout")}</a>
          </span>
          <span style="margin-left: 8px;">
            {getSupportedLocales().map((l) => (
              <a href={`?lang=${l}`} style={`margin-left: 4px; ${l === locale ? 'font-weight: bold;' : ''}`}>{l.toUpperCase()}</a>
            ))}
          </span>
        </nav>
        <div class="container">
          {props.flash && (
            <div class={`flash ${props.flash.type}`}>
              {props.flash.message}
            </div>
          )}
          {props.children}
        </div>
      </body>
    </html>
  );
};
