import type { AdminService, Cell, Issue, Peer, Status } from '../service/contracts';
export interface AdminState { busy: boolean; status: Status | null; cells: Cell[]; peers: Peer[]; error: string; detail: Cell | null; issues: Issue[] }
const empty = (): AdminState => ({ busy: false, status: null, cells: [], peers: [], error: '', detail: null, issues: [] });
export class AdminPresenter {
  state = empty();
  private listeners = new Set<() => void>();
  constructor(private service: AdminService) {}
  subscribe = (listener: () => void) => { this.listeners.add(listener); return () => { this.listeners.delete(listener); }; };
  private update(patch: Partial<AdminState>) { this.state = { ...this.state, ...patch }; this.listeners.forEach(listener => listener()); }
  async connect(token: string) {
    if (!token.trim()) { this.update({ error: 'Enter your local management token.' }); return false; }
    this.service.setToken(token.trim());
    this.update({ busy: true, error: '' });
    try {
      const [status, cells, peers] = await Promise.all([this.service.status(), this.service.cells(), this.service.peers()]);
      this.update({ status, cells, peers, busy: false });
      return true;
    } catch (error) {
      this.disconnect();
      this.update({ error: error instanceof Error ? error.message : 'Connection failed.' });
      return false;
    }
  }
  private async run(action: () => Promise<void>) {
    if (this.state.busy) return false;
    this.update({ busy: true, error: '' });
    try { await action(); return true; }
    catch (error) { this.update({ error: error instanceof Error ? error.message : 'Request failed.' }); return false; }
    finally { this.update({ busy: false }); }
  }
  async createCell(name: string) {
    if (!name.trim()) { this.update({ error: 'Repository name is required.' }); return false; }
    return this.run(async () => {
      const cell = await this.service.createCell(name.trim());
      const cells = [...this.state.cells.filter(item => item.id !== cell.id), cell];
      this.update({ cells, status: this.state.status ? { ...this.state.status, cells: cells.length } : null });
    });
  }
  async openCell(id: string) {
    if (this.state.detail?.id === id) { this.update({ detail: null, issues: [] }); return true; }
    this.update({ detail: null, issues: [] });
    return this.run(async () => {
      const [detail, issues] = await Promise.all([this.service.cell(id), this.service.issues(id)]);
      this.update({ detail, issues });
    });
  }
  async createIssue(title: string, body: string) {
    const id = this.state.detail?.id;
    if (!id || !title.trim()) { this.update({ error: 'Select a repository and enter an issue title.' }); return false; }
    return this.run(async () => {
      const issue = await this.service.createIssue(id, title.trim(), body);
      this.update({ issues: [...this.state.issues, issue] });
    });
  }
  async createPeer(input: Peer) {
    const peer = { id: input.id.trim(), url: input.url.trim(), public_key: input.public_key.trim() };
    let validUrl = false;
    try { validUrl = ['http:', 'https:'].includes(new URL(peer.url).protocol); } catch { /* invalid URL */ }
    if (!peer.id || !peer.public_key || !validUrl) { this.update({ error: 'Peer ID, HTTP(S) URL, and public key are required.' }); return false; }
    return this.run(async () => {
      const saved = await this.service.createPeer(peer);
      this.update({ peers: [...this.state.peers.filter(item => item.id !== saved.id), saved] });
    });
  }
  disconnect() { this.service.setToken(''); this.update(empty()); }
}
