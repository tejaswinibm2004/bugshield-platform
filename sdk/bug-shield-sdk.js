/**
 * BugShield SaaS - Embedded Client Integration SDK
 * Permission-based telemetry & issue reporting widget for customer applications.
 */

(function () {
  if (window.BugShieldSDK) return;

  class BugShield {
    init(config = {}) {
      this.appId = config.appId || 'APP-UNKNOWN';
      this.sdkKey = config.sdkKey || '';
      // Scoped ingestion key (preferred). Revocable, origin-scoped, rate limited.
      this.ingestionKey = config.ingestionKey || '';
      // ID of the <div> the report button renders into. When the div is absent
      // (older integrations), the button falls back to a floating action button.
      this.containerId = config.containerId || 'bugshield-widget';
      const cs = document.currentScript;
      // For inline <script> blocks currentScript exists but has no src —
      // only use it when it actually carries one.
      const currentScript = (cs && cs.src)
        ? cs
        : Array.from(document.scripts).find(s => s.src && s.src.includes('bug-shield-sdk.js'));
      const defaultHost = currentScript ? new URL(currentScript.src).origin : window.location.origin;
      let endpoint = config.endpoint || `${defaultHost}/api/v1/issues`;

      // Automatic Mixed Content Protection (upgrade http:// to https:// on HTTPS websites)
      if (window.location.protocol === 'https:' && endpoint.startsWith('http://') && !endpoint.includes('localhost')) {
        endpoint = endpoint.replace('http://', 'https://');
      }
      this.endpoint = endpoint;
      this.logs = [];

      console.log(`[BugShield SDK] Active for App: ${this.appId} | Endpoint: ${this.endpoint}`);
      this.interceptConsole();
      this.renderWidget();
    }

    interceptConsole() {
      const origError = console.error;
      console.error = (...args) => {
        this.logs.push({ type: 'ERROR', text: args.join(' '), time: new Date().toISOString() });
        origError.apply(console, args);
      };
    }

    renderWidget() {
      // Inject CSS
      const style = document.createElement('style');
      style.textContent = `
        .bugshield-floating-btn {
          position: fixed;
          bottom: 24px;
          right: 24px;
          background: linear-gradient(135deg, #6366f1, #a855f7);
          color: #ffffff;
          border: none;
          border-radius: 50px;
          padding: 12px 20px;
          font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
          font-weight: 600;
          font-size: 14px;
          cursor: pointer;
          box-shadow: 0 10px 25px -5px rgba(99, 102, 241, 0.5);
          display: flex;
          align-items: center;
          gap: 8px;
          z-index: 999999;
          transition: transform 0.2s ease, box-shadow 0.2s ease;
        }
        .bugshield-floating-btn:hover {
          transform: translateY(-2px);
          box-shadow: 0 15px 30px -5px rgba(99, 102, 241, 0.7);
        }
        .bugshield-inline-btn {
          background: linear-gradient(135deg, #6366f1, #a855f7);
          color: #ffffff;
          border: none;
          border-radius: 8px;
          padding: 10px 16px;
          font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
          font-weight: 600;
          font-size: 14px;
          cursor: pointer;
          display: inline-flex;
          align-items: center;
          gap: 8px;
        }
        .bugshield-inline-btn:hover {
          filter: brightness(1.1);
        }
        .bugshield-modal-backdrop {
          position: fixed;
          top: 0; left: 0; right: 0; bottom: 0;
          background: rgba(15, 23, 42, 0.75);
          backdrop-filter: blur(6px);
          display: flex;
          align-items: center;
          justify-content: center;
          z-index: 1000000;
          opacity: 0;
          pointer-events: none;
          transition: opacity 0.25s ease;
        }
        .bugshield-modal-backdrop.open {
          opacity: 1;
          pointer-events: auto;
        }
        .bugshield-modal-card {
          background: #0f172a;
          border: 1px solid rgba(255, 255, 255, 0.12);
          border-radius: 16px;
          width: 90%;
          max-width: 520px;
          padding: 24px;
          box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5);
          color: #f8fafc;
          font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
          transform: scale(0.95);
          transition: transform 0.25s cubic-bezier(0.16, 1, 0.3, 1);
        }
        .bugshield-modal-backdrop.open .bugshield-modal-card {
          transform: scale(1);
        }
        .bugshield-header {
          display: flex;
          justify-content: space-between;
          align-items: center;
          margin-bottom: 16px;
          border-bottom: 1px solid rgba(255, 255, 255, 0.08);
          padding-bottom: 12px;
        }
        .bugshield-title {
          font-size: 18px;
          font-weight: 700;
          background: linear-gradient(90deg, #818cf8, #c084fc);
          -webkit-background-clip: text;
          -webkit-text-fill-color: transparent;
          margin: 0;
        }
        .bugshield-close {
          background: none; border: none; color: #94a3b8; font-size: 20px; cursor: pointer;
        }
        .bugshield-form-group {
          margin-bottom: 14px;
        }
        .bugshield-label {
          display: block; font-size: 12px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px; color: #94a3b8; margin-bottom: 6px;
        }
        .bugshield-input, .bugshield-textarea {
          width: 100%;
          background: rgba(30, 41, 59, 0.8);
          border: 1px solid rgba(255, 255, 255, 0.1);
          border-radius: 8px;
          padding: 10px 12px;
          color: #f8fafc;
          font-size: 14px;
          box-sizing: border-box;
          outline: none;
        }
        .bugshield-input:focus, .bugshield-textarea:focus {
          border-color: #6366f1;
        }
        .bugshield-textarea { height: 70px; resize: vertical; }
        .bugshield-submit-btn {
          width: 100%;
          background: linear-gradient(135deg, #6366f1, #4f46e5);
          color: #fff;
          border: none;
          padding: 12px;
          border-radius: 8px;
          font-weight: 600;
          cursor: pointer;
          font-size: 15px;
          margin-top: 8px;
        }
        .bugshield-privacy-note {
          font-size: 11px; color: #64748b; margin-top: 10px; text-align: center;
        }
      `;
      document.head.appendChild(style);

      // Create Button: inside the site's own div when present, otherwise as a
      // floating action button (backwards compatible with older integrations).
      const btn = document.createElement('button');
      const mount = document.getElementById(this.containerId);
      if (mount) {
        btn.className = 'bugshield-inline-btn';
        mount.appendChild(btn);
      } else {
        btn.className = 'bugshield-floating-btn';
      }
      btn.innerHTML = `
        <svg width="18" height="18" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path>
        </svg>
        Report an Issue
      `;
      if (!mount) document.body.appendChild(btn);

      // Create Modal
      const backdrop = document.createElement('div');
      backdrop.className = 'bugshield-modal-backdrop';
      backdrop.innerHTML = `
        <div class="bugshield-modal-card">
          <div class="bugshield-header">
            <h3 class="bugshield-title">Report an Issue</h3>
            <button class="bugshield-close">&times;</button>
          </div>
          <form id="bugshield-form">
            <div class="bugshield-form-group">
              <label class="bugshield-label">Describe the issue in your own words</label>
              <textarea class="bugshield-textarea" id="bs-issue-input" placeholder="e.g. Payment failed during checkout, or delivery fee error..." required style="height: 100px; font-size: 14px; padding: 12px;"></textarea>
            </div>
            <button type="submit" class="bugshield-submit-btn" id="bs-submit">Submit Bug Report to Platform</button>
            <div class="bugshield-privacy-note">
              🛡️ BugShield AI Multi-Agent system will process this report instantly.
            </div>
          </form>
        </div>
      `;
      document.body.appendChild(backdrop);

      // Listeners
      btn.onclick = () => backdrop.classList.add('open');
      backdrop.querySelector('.bugshield-close').onclick = () => backdrop.classList.remove('open');

      const form = backdrop.querySelector('#bugshield-form');
      form.onsubmit = async (e) => {
        e.preventDefault();
        const issueText = document.getElementById('bs-issue-input').value.trim();
        if (!issueText) return;

        const submitBtn = backdrop.querySelector('#bs-submit');
        submitBtn.disabled = true;
        submitBtn.textContent = 'Transmitting to AI Multi-Agent Platform...';

        const payload = {
          application_id: this.appId,
          sdk_key: this.sdkKey,
          // Preferred: a scoped ingestion key with its own origin allow-list and
          // rate limit. Falls back to the legacy SDK key when not configured.
          ...(this.ingestionKey ? { ingestion_key: this.ingestionKey } : {}),
          title: issueText,
          description: issueText,
          page_url: window.location.pathname,
          steps_to_reproduce: 'Reported via end-user widget',
          stack_trace: window.lastRecordedErrorStack || '',
          release: window.__BUGSHIELD_RELEASE__ || undefined,
          logs: this.logs.slice(0, 20),
          browser_info: {
            userAgent: navigator.userAgent,
            viewport: `${window.innerWidth}x${window.innerHeight}`
          }
        };

        try {
          const res = await fetch(this.endpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'bugshield' },
            body: JSON.stringify(payload)
          });
          const data = await res.json();
          if (data.status === 'DEDUPLICATED') {
            alert(`This error was already reported as #${data.issueId}. We added this occurrence to it.`);
            form.reset();
            backdrop.classList.remove('open');
          } else if (res.status === 429) {
            alert('Too many reports were just sent. Please wait a moment before reporting again.');
          } else if (data.success) {
            alert(`✅ Issue Report #${data.issueId} submitted successfully!\nOur AI Multi-Agent platform has received your report and initiated automated diagnosis.`);
            form.reset();
            backdrop.classList.remove('open');
          } else {
            alert('Error submitting issue: ' + data.message);
          }
        } catch (err) {
          alert('Failed to reach platform API: ' + err.message);
        } finally {
          submitBtn.disabled = false;
          submitBtn.textContent = 'Submit Bug Report to Platform';
        }
      };
    }
  }

  window.BugShieldSDK = new BugShield();
})();
