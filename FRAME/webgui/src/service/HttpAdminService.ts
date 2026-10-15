import type { AdminService, Cell, Issue, Peer, Status } from './contracts';
export class HttpAdminService implements AdminService {
  private token = '';
  constructor(private transport: typeof fetch = fetch) {}
  setToken(token: string) { this.token = token; }
  private async request<T>(path: string, body?: unknown): Promise<T> {
    if (!this.token) throw new Error('Enter your local management token.');
    const response = await this.transport(`/api${path}`, {
      method: body === undefined ? 'GET' : 'POST',
      headers: { Authorization: `Bearer ${this.token}`, ...(body === undefined ? {} : { 'Content-Type': 'application/json' }) },
      body: body === undefined ? undefined : JSON.stringify(body),
      cache: 'no-store',
      credentials: 'omit',
    });
    if (!response.ok) {
      let reason = response.statusText;
      try { const data = await response.json(); reason = typeof data.error === 'string' ? data.error : reason; } catch { /* non-JSON error */ }
      throw new Error(`HTTP ${response.status}: ${reason || 'Request failed'}`);
    }
    return response.json() as Promise<T>;
  }
  status() { return this.request<Status>('/status'); }
  cells() { return this.request<Cell[]>('/cells'); }
  peers() { return this.request<Peer[]>('/peers'); }
  createCell(name: string) { return this.request<Cell>('/cells', { name }); }
  cell(id: string) { return this.request<Cell>(`/cells/${encodeURIComponent(id)}`); }
  issues(id: string) { return this.request<Issue[]>(`/cells/${encodeURIComponent(id)}/issues`); }
  createIssue(id: string, title: string, body: string) { return this.request<Issue>(`/cells/${encodeURIComponent(id)}/issues`, { title, body }); }
  createPeer(peer: Peer) { return this.request<Peer>('/peers', peer); }
}
