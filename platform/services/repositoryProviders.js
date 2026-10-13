/**
 * Repository provider abstraction.
 *
 * A provider is a real, verified connection to a source host. `isConfigured()`
 * and `verify()` must never report success without an actual authenticated call,
 * and `listRepositories()` must return data that came from the provider's API.
 *
 * Adding GitLab or another host means implementing the same interface and
 * registering it in PROVIDERS; nothing else in the platform changes.
 */

export class RepositoryProvider {
  get name() { throw new Error('not implemented'); }
  /** False unless credentials for this provider exist in the environment. */
  isConfigured() { return false; }
  /** Performs a real authenticated call. Never returns a fabricated success. */
  async verify() { return { ok: false, error: 'not implemented' }; }
  async listRepositories() { throw new Error('not implemented'); }
  /** Reads one file at a specific ref. Returns { ok, content, sha, error }. */
  async getFile() { return { ok: false, error: 'not implemented' }; }
  async getCommitSha() { return { ok: false, error: 'not implemented' }; }
  /** Creates a branch and a pull request. Returns { ok, branch, prUrl, error }. */
  async createPatchPullRequest() { return { ok: false, error: 'not implemented' }; }
}

/**
 * GitHub provider. Supports two credential modes:
 *  - GitHub App installation token (recommended, short-lived)
 *  - Personal access token (development only)
 */
export class GitHubProvider extends RepositoryProvider {
  get name() { return 'github'; }
  get api() { return process.env.GITHUB_API_URL || 'https://api.github.com'; }

  get authMode() {
    if (process.env.GITHUB_APP_ID && process.env.GITHUB_APP_INSTALLATION_ID && process.env.GITHUB_APP_PRIVATE_KEY) return 'github-app';
    if (process.env.GITHUB_TOKEN) return 'pat';
    return null;
  }

  isConfigured() { return this.authMode !== null; }

  async headers() {
    if (this.authMode === 'pat') {
      return { Authorization: `Bearer ${process.env.GITHUB_TOKEN}`, Accept: 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28' };
    }
    const token = await this.appInstallationToken();
    if (!token) return null;
    return { Authorization: `Bearer ${token}`, Accept: 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28' };
  }

  /** Exchanges the App private key for a short-lived installation token. */
  async appInstallationToken() {
    if (this.authMode !== 'github-app') return null;
    const crypto = await import('node:crypto');
    const key = process.env.GITHUB_APP_PRIVATE_KEY.replace(/\\n/g, '\n');
    const now = Math.floor(Date.now() / 1000);
    const header = Buffer.from(JSON.stringify({ alg: 'RS256', typ: 'JWT' })).toString('base64url');
    const payload = Buffer.from(JSON.stringify({
      iat: now - 60, exp: now + 540, iss: process.env.GITHUB_APP_ID
    })).toString('base64url');
    const signature = crypto.sign('RSA-SHA256', Buffer.from(`${header}.${payload}`), key).toString('base64url');
    const jwt = `${header}.${payload}.${signature}`;

    try {
      const res = await fetch(`${this.api}/app/installations/${process.env.GITHUB_APP_INSTALLATION_ID}/access_tokens`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${jwt}`, Accept: 'application/vnd.github+json' }
      });
      if (!res.ok) return null;
      const data = await res.json();
      return data.token || null;
    } catch {
      return null; // unreachable GitHub is treated as "not authenticated"
    }
  }

  async request(pathname) {
    const headers = await this.headers();
    if (!headers) return { ok: false, status: 0, error: 'GitHub credentials are not configured.' };
    try {
      const res = await fetch(`${this.api}${pathname}`, { headers });
      const text = await res.text();
      let body;
      try { body = JSON.parse(text); } catch { body = text; }
      return { ok: res.ok, status: res.status, body };
    } catch (e) {
      // Network failure must be reported as a failed verification, never thrown,
      // so that callers such as the integrations status endpoint stay correct.
      return { ok: false, status: 0, error: `Could not reach GitHub: ${e.message}` };
    }
  }

  async verify() {
    if (!this.isConfigured()) {
      return { ok: false, configured: false, error: 'No GitHub credentials configured. Set GITHUB_APP_ID, GITHUB_APP_INSTALLATION_ID and GITHUB_APP_PRIVATE_KEY, or GITHUB_TOKEN for development.' };
    }
    const res = await this.request('/installation/repositories?per_page=1');
    if (!res.ok) return { ok: false, configured: true, error: `GitHub rejected the credentials (HTTP ${res.status}).`, status: res.status };
    const count = Array.isArray(res.body?.repositories) ? res.body.repositories.length : 0;
    return { ok: true, configured: true, mode: this.authMode, visibleRepositories: count };
  }

  async listRepositories() {
    const res = await this.request('/installation/repositories?per_page=100');
    if (!res.ok) return { ok: false, error: res.error || `HTTP ${res.status}`, repositories: [] };
    return {
      ok: true,
      repositories: (res.body?.repositories || []).map(r => ({
        fullName: r.full_name, private: !!r.private, defaultBranch: r.default_branch,
        cloneUrl: r.clone_url, id: r.id
      }))
    };
  }

  async getCommitSha(owner, repo, ref) {
    const res = await this.request(`/repos/${owner}/${repo}/commits/${encodeURIComponent(ref || 'HEAD')}`);
    if (!res.ok) return { ok: false, error: `HTTP ${res.status}` };
    return { ok: true, sha: res.body?.sha, date: res.body?.commit?.committer?.date };
  }

  async getFile(owner, repo, filePath, ref) {
    const res = await this.request(`/repos/${owner}/${repo}/contents/${filePath}?ref=${encodeURIComponent(ref || 'HEAD')}`);
    if (!res.ok) return { ok: false, error: `HTTP ${res.status}`, content: null };
    if (res.body?.type !== 'file' || typeof res.body.content !== 'string') {
      return { ok: false, error: 'Path is not a file', content: null };
    }
    return { ok: true, content: Buffer.from(res.body.content, 'base64').toString('utf-8'), sha: res.body.sha };
  }

  async createPatchPullRequest({ owner, repo, baseBranch, branch, title, body, files }) {
    // 1. Resolve the base branch SHA so the new branch starts from real history.
    const base = await this.getCommitSha(owner, repo, baseBranch);
    if (!base.ok) return { ok: false, error: `Cannot resolve base branch: ${base.error}` };

    // 2. Create branch, commit each file, then open the pull request.
    return this._write(owner, repo, branch, base.sha, baseBranch, title, body, files);
  }

  async _write(owner, repo, branch, baseSha, baseBranch, title, body, files) {
    const headers = await this.headers();
    if (!headers) return { ok: false, error: 'GitHub credentials are not configured.' };
    const post = async (pathname, payload) => {
      const res = await fetch(`${this.api}${pathname}`, {
        method: 'POST', headers: { ...headers, 'Content-Type': 'application/json' }, body: JSON.stringify(payload)
      });
      const t = await res.text();
      let b; try { b = JSON.parse(t); } catch { b = t; }
      return { ok: res.ok, status: res.status, body: b };
    };

    const ref = await post(`/repos/${owner}/${repo}/git/refs`, { ref: `refs/heads/${branch}`, sha: baseSha });
    if (!ref.ok && ref.status !== 422) return { ok: false, error: `Branch creation failed (HTTP ${ref.status})` };

    for (const f of files) {
      const put = await fetch(`${this.api}/repos/${owner}/${repo}/contents/${f.path}`, {
        method: 'PUT',
        headers: { ...headers, 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: f.message, content: Buffer.from(f.content, 'utf-8').toString('base64'), branch, sha: f.sha })
      });
      if (!put.ok) return { ok: false, error: `Could not write ${f.path} (HTTP ${put.status})` };
    }

    const pr = await post(`/repos/${owner}/${repo}/pulls`, { title, body, head: branch, base: baseBranch });
    if (!pr.ok) return { ok: false, error: `Pull request creation failed (HTTP ${pr.status})` };
    return { ok: true, branch, prUrl: pr.body?.html_url, prNumber: pr.body?.number };
  }
}

/**
 * Placeholder for a future provider. It is intentionally NOT implemented and
 * reports itself as unavailable, so the UI cannot imply GitLab is supported.
 */
export class GitLabProvider extends RepositoryProvider {
  get name() { return 'gitlab'; }
  isConfigured() { return !!process.env.GITLAB_TOKEN && !!process.env.GITLAB_PROJECT_ID; }
  async verify() {
    return {
      ok: false, configured: this.isConfigured(),
      error: 'GitLab integration is planned but not implemented. Only the GitHub provider can be used today.'
    };
  }
}

const PROVIDERS = {
  github: new GitHubProvider(),
  gitlab: new GitLabProvider()
};

export function getProvider(name = 'github') {
  return PROVIDERS[name] || null;
}

export function listProviderStatus() {
  return Object.values(PROVIDERS).map(p => ({
    name: p.name,
    implemented: !(p instanceof GitLabProvider),
    configured: p.isConfigured()
  }));
}