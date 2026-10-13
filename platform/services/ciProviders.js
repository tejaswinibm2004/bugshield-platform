/**
 * CI/CD provider adapters.
 *
 * The platform must never claim a CI system is connected unless it has actually
 * been contacted. Each adapter therefore exposes isConfigured() (credentials
 * present) and verify() (a real authenticated call).
 */
export class CiProvider {
  get name() { return 'none'; }
  isConfigured() { return false; }
  async verify() { return { ok: false, configured: false, error: 'No CI provider implemented.' }; }
  async triggerBuild() { return { ok: false, error: 'not implemented' }; }
  async getBuildStatus() { return { ok: false, error: 'not implemented' }; }
}

export class JenkinsProvider extends CiProvider {
  get name() { return 'jenkins'; }
  isConfigured() { return !!(process.env.JENKINS_URL && (process.env.JENKINS_USER || process.env.JENKINS_TOKEN)); }

  authHeader() {
    const user = process.env.JENKINS_USER;
    const token = process.env.JENKINS_TOKEN;
    if (user && token) return `Basic ${Buffer.from(`${user}:${token}`).toString('base64')}`;
    if (token) return `Bearer ${token}`;
    return null;
  }

  async verify() {
    if (!this.isConfigured()) {
      return { ok: false, configured: false, error: 'Jenkins is not configured. Set JENKINS_URL and JENKINS_TOKEN.' };
    }
    try {
      const res = await fetch(`${process.env.JENKINS_URL}/api/json`, {
        headers: { Authorization: this.authHeader() }
      });
      if (!res.ok) return { ok: false, configured: true, error: `Jenkins rejected the credentials (HTTP ${res.status})` };
      const body = await res.json();
      return { ok: true, configured: true, mode: 'Basic/Bearer token', jenkinsVersion: body.version || 'unknown' };
    } catch (e) {
      return { ok: false, configured: true, error: `Could not reach Jenkins: ${e.message}` };
    }
  }

  async triggerBuild(params = {}) {
    if (!this.isConfigured()) return { ok: false, error: 'Jenkins is not configured.' };
    const token = process.env.JENKINS_CRUMB_TOKEN;
    const headers = { Authorization: this.authHeader(), 'Content-Type': 'application/x-www-form-urlencoded' };
    if (token) headers['Jenkins-Crumb'] = token;
    const res = await fetch(`${process.env.JENKINS_URL}/job/${process.env.JENKINS_JOB || 'build'}`, {
      method: 'POST', headers, body: new URLSearchParams(params).toString()
    });
    if (!res.ok) return { ok: false, error: `Jenkins build trigger failed (HTTP ${res.status})` };
    const queueUrl = res.headers.get('location');
    return { ok: true, queueUrl, queueId: queueUrl ? queueUrl.split('/').pop() : null };
  }
}

export class GitHubActionsProvider extends CiProvider {
  get name() { return 'github-actions'; }
  isConfigured() { return !!(process.env.GITHUB_TOKEN && process.env.GITHUB_REPOSITORY); }

  async verify() {
    if (!this.isConfigured()) {
      return { ok: false, configured: false, error: 'GitHub Actions is not configured. Set GITHUB_TOKEN and GITHUB_REPOSITORY.' };
    }
    const api = process.env.GITHUB_API_URL || 'https://api.github.com';
    try {
      const res = await fetch(`${api}/repos/${process.env.GITHUB_REPOSITORY}/actions/workflows`, {
        headers: { Authorization: `Bearer ${process.env.GITHUB_TOKEN}`, Accept: 'application/vnd.github+json' }
      });
      if (!res.ok) return { ok: false, configured: true, error: `GitHub rejected the credentials (HTTP ${res.status})` };
      const body = await res.json();
      return { ok: true, configured: true, workflows: (body.workflows || []).map(w => w.name) };
    } catch (e) {
      return { ok: false, configured: true, error: `Could not reach GitHub: ${e.message}` };
    }
  }

  async triggerBuild({ workflowId, ref = 'main', inputs = {} }) {
    if (!this.isConfigured()) return { ok: false, error: 'GitHub Actions is not configured.' };
    const api = process.env.GITHUB_API_URL || 'https://api.github.com';
    const res = await fetch(`${api}/repos/${process.env.GITHUB_REPOSITORY}/actions/workflows/${workflowId}/dispatches`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${process.env.GITHUB_TOKEN}`, Accept: 'application/vnd.github+json', 'Content-Type': 'application/json' },
      body: JSON.stringify({ ref, inputs })
    });
    if (!res.ok) return { ok: false, error: `Workflow dispatch failed (HTTP ${res.status})` };
    return { ok: true };
  }
}

const PROVIDERS = {
  jenkins: new JenkinsProvider(),
  'github-actions': new GitHubActionsProvider()
};

export function getCiProvider(name) { return PROVIDERS[name] || null; }

export function listCiStatus() {
  return Object.values(PROVIDERS).map(p => ({ name: p.name, implemented: true, configured: p.isConfigured() }));
}