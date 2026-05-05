import type { FC } from "hono/jsx";
import { raw } from "hono/html";
import { Layout } from "./layout.js";
import { t, type Locale } from "../lib/i18n.js";

/**
 * One-time secret reveal view.
 *
 * Renders directly on POST response — secret is NEVER placed in URL/Location/redirect.
 * This prevents the secret from appearing in:
 *   - reverse-proxy access logs
 *   - browser history
 *   - Referer headers on outbound clicks
 *   - any HTTP middleware/observability tooling that logs URLs
 *
 * Pairs with:
 *   - "I have saved it" confirmation gate before "Continue" enables
 *   - Download-as-file button (so user has tangible artifact to back up)
 *   - Copy-to-clipboard
 *   - Page-leave warning if confirmation not checked
 */
export interface SecretRevealProps {
  locale: Locale;
  /** Page heading, e.g. "Master key for project X" */
  title: string;
  /** Short paragraph explaining what this secret is for */
  description: string;
  /** Strong warning emphasising one-time visibility */
  warning: string;
  /** The actual secret value to reveal */
  secret: string;
  /** Filename (without extension) for the download — e.g. "seklok-master-key-myproject" */
  downloadFilename: string;
  /** Where the user should go after confirming they've saved it */
  continueUrl: string;
  /** Optional label for continue button (defaults to translated "Continue") */
  continueLabel?: string;
}

export const SecretRevealPage: FC<SecretRevealProps> = (props) => {
  const { locale } = props;
  const continueLabel = props.continueLabel ?? t(locale, "secret_reveal.continue");

  // Inline JSON to avoid quoting issues in the inline script
  const dataJson = JSON.stringify({
    secret: props.secret,
    filename: props.downloadFilename,
    continueUrl: props.continueUrl,
  });

  return (
    <Layout title={props.title} locale={locale}>
      <h1>{props.title}</h1>

      <div class="warning" style="border-left: 4px solid #e63946; padding: 16px;">
        <p style="margin-bottom: 8px;"><strong>{props.warning}</strong></p>
        <p>{props.description}</p>
      </div>

      <fieldset style="margin-top: 16px;">
        <div class="form-group">
          <label for="reveal_secret_input">{t(locale, "secret_reveal.value_label")}</label>
          <div class="copyable" style="margin-top: 4px;">
            <input id="reveal_secret_input" type="password" value={props.secret} readonly style="flex: 1; font-family: monospace;" />
            <button type="button" class="btn btn-sm" id="reveal_toggle_btn">{t(locale, "secret_reveal.show")}</button>
            <button type="button" class="btn btn-sm" id="reveal_copy_btn">{t(locale, "projects.btn_copy")}</button>
            <button type="button" class="btn btn-sm" id="reveal_download_btn">{t(locale, "secret_reveal.download")}</button>
          </div>
          <p id="reveal_copy_status" style="font-size: 12px; color: #666; margin-top: 4px; min-height: 16px;"></p>
        </div>

        <div class="form-group" style="margin-top: 16px;">
          <label style="min-width: auto; cursor: pointer;">
            <input type="checkbox" id="reveal_confirm_checkbox" style="width: auto; margin-right: 8px;" />
            {t(locale, "secret_reveal.confirm_label")}
          </label>
        </div>

        <div class="form-actions">
          <a id="reveal_continue_btn" href={props.continueUrl} class="btn btn-primary" aria-disabled="true" style="opacity: 0.5; pointer-events: none;">{continueLabel}</a>
        </div>
      </fieldset>

      {raw(`<script>
        (function() {
          var data = ${dataJson};
          var input = document.getElementById('reveal_secret_input');
          var toggleBtn = document.getElementById('reveal_toggle_btn');
          var copyBtn = document.getElementById('reveal_copy_btn');
          var downloadBtn = document.getElementById('reveal_download_btn');
          var statusEl = document.getElementById('reveal_copy_status');
          var checkbox = document.getElementById('reveal_confirm_checkbox');
          var continueBtn = document.getElementById('reveal_continue_btn');

          var SHOW = ${JSON.stringify(t(locale, "secret_reveal.show"))};
          var HIDE = ${JSON.stringify(t(locale, "secret_reveal.hide"))};
          var COPIED = ${JSON.stringify(t(locale, "secret_reveal.copied"))};
          var COPY_FAIL = ${JSON.stringify(t(locale, "secret_reveal.copy_failed"))};
          var LEAVE_WARN = ${JSON.stringify(t(locale, "secret_reveal.leave_warning"))};

          var saved = false;

          // Show/hide toggle
          toggleBtn.addEventListener('click', function() {
            if (input.type === 'password') {
              input.type = 'text';
              toggleBtn.textContent = HIDE;
            } else {
              input.type = 'password';
              toggleBtn.textContent = SHOW;
            }
          });

          // Copy to clipboard (works without HTTPS via fallback)
          copyBtn.addEventListener('click', function() {
            var done = function(ok) {
              statusEl.textContent = ok ? COPIED : COPY_FAIL;
              setTimeout(function() { statusEl.textContent = ''; }, 2500);
            };
            if (navigator.clipboard && navigator.clipboard.writeText) {
              navigator.clipboard.writeText(data.secret).then(function() { done(true); }, function() { done(false); });
            } else {
              try {
                var prevType = input.type;
                input.type = 'text';
                input.select();
                var ok = document.execCommand('copy');
                input.type = prevType;
                done(ok);
              } catch (e) {
                done(false);
              }
            }
          });

          // Download as plain text file
          downloadBtn.addEventListener('click', function() {
            var blob = new Blob([data.secret + '\\n'], { type: 'text/plain;charset=utf-8' });
            var url = URL.createObjectURL(blob);
            var a = document.createElement('a');
            a.href = url;
            a.download = data.filename + '.txt';
            document.body.appendChild(a);
            a.click();
            setTimeout(function() {
              document.body.removeChild(a);
              URL.revokeObjectURL(url);
            }, 100);
          });

          // Gate the continue button on confirmation
          checkbox.addEventListener('change', function() {
            if (checkbox.checked) {
              saved = true;
              continueBtn.style.opacity = '1';
              continueBtn.style.pointerEvents = 'auto';
              continueBtn.removeAttribute('aria-disabled');
            } else {
              saved = false;
              continueBtn.style.opacity = '0.5';
              continueBtn.style.pointerEvents = 'none';
              continueBtn.setAttribute('aria-disabled', 'true');
            }
          });

          // Warn on navigation away if not confirmed
          window.addEventListener('beforeunload', function(e) {
            if (!saved) {
              e.preventDefault();
              e.returnValue = LEAVE_WARN;
              return LEAVE_WARN;
            }
          });

          // Allow continue link to bypass beforeunload (since user explicitly confirmed)
          continueBtn.addEventListener('click', function() {
            saved = true;
          });
        })();
      </script>`)}
    </Layout>
  );
};
