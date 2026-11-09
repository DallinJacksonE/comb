/** Same-origin JSON adapter for the FRAME management API; never stores bearer tokens. */
import type { AdminService, Blob, Cell, History, Issue, Peer, Profile, Role, Status, Tree } from './contracts';
/** Implements AdminService with encoded paths, cookie credentials, and no-store reads. */
export class HttpAdminService implements AdminService {
  /** Inject fetch for tests and notify the gate when the server returns HTTP 401. */
  constructor(private transport: typeof fetch = fetch, private onUnauthorized?: () => void) {}
  /** GET without a body, POST with JSON otherwise. The WebGUI marker is not
   * authorization by itself: the daemon also enforces browser provenance/session checks.
   * Non-2xx responses throw status-bearing errors, including JSON error text if present.
   */
  private async request<T>(path: string, body?: unknown): Promise<T> {
    const transport = this.transport; // Native fetch must not receive this service as its receiver.
    const response = await transport(`/api${path}`, {
      method: body === undefined ? 'GET' : 'POST',
      headers: { 'X-Comb-Webgui': '1', ...(body === undefined ? {} : { 'Content-Type': 'application/json' }) },
      body: body === undefined ? undefined : JSON.stringify(body),
      cache: 'no-store',
      credentials: 'same-origin',
    });
    if (response.status === 401) this.onUnauthorized?.();
    if (!response.ok) {
      let reason = response.statusText;
      try { const data = await response.json(); reason = typeof data.error === 'string' ? data.error : reason; } catch { /* non-JSON error */ }
      throw new Error(`HTTP ${response.status}: ${reason || 'Request failed'}`);
    }
    return response.json() as Promise<T>;
  }
  /** Fetch a commit-offset page, encoding revision independently of the CELL path. */
  history(id: string, revision: string, offset: number) {
    return this.request<History>(`/cells/${encodeURIComponent(id)}/history?${new URLSearchParams({ revision, offset: String(offset) })}`);
  }
  /** List committed directory entries with separately encoded query values. */
  tree(id: string, revision: string, path: string) { return this.request<Tree>(`/cells/${encodeURIComponent(id)}/tree?${new URLSearchParams({ revision, path })}`); }
  /** Fetch bounded file preview metadata and optional text content. */
  blob(id: string, revision: string, path: string) { return this.request<Blob>(`/cells/${encodeURIComponent(id)}/blob?${new URLSearchParams({ revision, path })}`); }
  /** POST a name and return the server's updated metadata/slug. */
  renameCell(id: string, name: string) { return this.request<Cell>(`/cells/${encodeURIComponent(id)}/rename`, { name }); }
  /** POST exact-name confirmation for local deletion. */
  deleteCell(id: string, confirmation: string) { return this.request<{ deleted: string }>(`/cells/${encodeURIComponent(id)}/delete`, { confirmation }); }
  /** Wrap the identity profile with its requested role. */
  grantMember(id: string, profile: Profile, role: Role) { return this.request<Cell>(`/cells/${encodeURIComponent(id)}/members`, { profile, role }); }
  /** Send the FRAME profile directly, unlike the member grant wrapper. */
  registerFrame(id: string, profile: Profile) { return this.request<Cell>(`/cells/${encodeURIComponent(id)}/frames`, profile); }
  /** Revoke using the API's identity_id field name. */
  revokeMember(id: string, identityId: string) { return this.request<Cell>(`/cells/${encodeURIComponent(id)}/revoke`, { identity_id: identityId }); }
  /** Fetch opaque encrypted backup JSON. */
  backup(id: string) { return this.request<unknown>(`/cells/${encodeURIComponent(id)}/backup`); }
  /** Read unlocked daemon identity/capabilities. */
  status() { return this.request<Status>('/status'); }
  /** List this FRAME's repository metadata. */
  cells() { return this.request<Cell[]>('/cells'); }
  /** List configured peers, without probing connectivity. */
  peers() { return this.request<Peer[]>('/peers'); }
  /** Create a named CELL repository. */
  createCell(name: string) { return this.request<Cell>('/cells', { name }); }
  /** Fetch one repository by encoded stable ID. */
  cell(id: string) { return this.request<Cell>(`/cells/${encodeURIComponent(id)}`); }
  /** List plain-text issues. */
  issues(id: string) { return this.request<Issue[]>(`/cells/${encodeURIComponent(id)}/issues`); }
  /** Create an issue and return its authoritative server record. */
  createIssue(id: string, title: string, body: string) { return this.request<Issue>(`/cells/${encodeURIComponent(id)}/issues`, { title, body }); }
  /** Save peer ID, endpoint, and public key as configuration. */
  createPeer(peer: Peer) { return this.request<Peer>('/peers', peer); }
}
