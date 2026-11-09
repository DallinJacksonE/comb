/** Repository navigation and mutations without React or direct HTTP dependencies. */
import type { AdminService, Blob, Cell, History, Issue, Profile, Role, Tree } from '../service/contracts';
/** Route-selected repository surface; code/history reads use revision query parameters. */
export type Tab = 'code' | 'issues' | 'settings' | 'history' | 'branches';
/** Current navigation snapshot: revision may resolve to a ref, path is repository-relative,
 * and historyOffset is a commit offset rather than a page number. Null read surfaces
 * distinguish unloaded data from an empty result returned by the server.
 */
export interface RepositoryState { busy: boolean; error: string; cell: Cell | null; tree: Tree | null; blob: Blob | null; readme: Blob | null; issues: Issue[]; revision: string; path: string; history: History | null; historyOffset: number }
/** Publish immutable snapshots and prevent older navigation/mutations overwriting new pages. */
export class RepositoryPresenter {
  /** Snapshot observed by views; mutations publish through update rather than editing it. */
  state: RepositoryState = {busy:false,error:'',cell:null,tree:null,blob:null,readme:null,issues:[],revision:'',path:'',history:null,historyOffset:0};
  private listeners = new Set<() => void>();
  /** Navigation epoch captured by each asynchronous operation. */
  private generation = 0;
  /** Inject the service contract so navigation logic can be exercised without a browser. */
  constructor(private service: AdminService) {}
  /** Subscribe to snapshots; return a cleanup callback suitable for React external stores. */
  subscribe = (listener: () => void) => { this.listeners.add(listener); return () => {this.listeners.delete(listener);}; };
  /** Merge a patch and synchronously notify subscribers. */
  private update(patch: Partial<RepositoryState>) { this.state = {...this.state,...patch}; this.listeners.forEach(fn=>fn()); }
  /** A completed request may not mutate a different navigation's state. */
  private async run<T>(action: (cell: Cell, update: (patch: Partial<RepositoryState>) => void) => Promise<T>): Promise<T | false> {
    if (this.state.busy || !this.state.cell) return false;
    const generation = this.generation;
    const update = (patch: Partial<RepositoryState>) => { if (generation === this.generation) this.update(patch); };
    this.update({busy:true,error:''});
    try {
      const result = await action(this.state.cell, update);
      return generation === this.generation ? result : false;
    }
    catch (error) { update({error:error instanceof Error ? error.message : 'Request failed.'}); return false; }
    finally { update({busy:false}); }
  }
  /** Publish validation feedback without calling the server. */
  private invalid(message: string) { this.update({error:message}); return false as const; }
  /** Rename using a trimmed nonblank name and retain the server's effective name/slug. */
  async rename(name: string) {
    if (!name.trim()) return this.invalid('Repository name is required.');
    return this.run(async (cell, update)=>{ update({cell:await this.service.renameCell(cell.id,name.trim())}); return true; });
  }
  /** Require the exact current name, verify the deleted ID, and refresh the list on success. */
  async delete(confirmation: string) {
    if (confirmation !== this.state.cell?.name) return this.invalid('Type the exact repository name to confirm local deletion.');
    return this.run(async cell=>{
      const result = await this.service.deleteCell(cell.id,confirmation);
      if (result.deleted !== cell.id) throw new Error('Deletion response did not match this repository.');
      await this.service.cells(); return true;
    });
  }
  /** Parse an object-shaped profile; signature and domain validation belong to the backend. */
  private profile(text: string): Profile {
    const value: unknown = JSON.parse(text);
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Profile must be a JSON object.');
    return value as Profile;
  }
  /** Grant read/write membership from exported identity profile JSON. */
  async grant(text: string, role: Role) { return this.run(async (cell, update)=>{update({cell:await this.service.grantMember(cell.id,this.profile(text),role)});return true;}); }
  /** Register an exported FRAME profile without adding a transport wrapper around it. */
  async registerFrame(text: string) { return this.run(async (cell, update)=>{update({cell:await this.service.registerFrame(cell.id,this.profile(text))});return true;}); }
  /** Revoke a nonblank identity ID; backend permissions remain authoritative. */
  async revoke(identity: string) {
    if (!identity.trim()) return this.invalid('Identity ID is required.');
    return this.run(async (cell, update)=>{update({cell:await this.service.revokeMember(cell.id,identity.trim())});return true;});
  }
  /** Return the opaque encrypted snapshot, or false on failure/busy/no repository. */
  async exportBackup() { return this.run(cell=>this.service.backup(cell.id)); }
  /** Create a plain-text issue and append only the successful server response. */
  async createIssue(title: string, body: string) {
    if (!title.trim()) return this.invalid('Issue title is required.');
    return this.run(async (cell, update)=>{const issue=await this.service.createIssue(cell.id,title.trim(),body);update({issues:[...this.state.issues,issue]});return true;});
  }
  /** Start a navigation, clearing old data and loading only the requested tab.
   * Empty revision prefers main, then the first sorted branch; code README reads
   * pin the tree's resolved commit. Only the newest generation may publish results.
   * @param file Whether path selects a blob instead of a directory.
   * @param offset History commit offset supplied by the route.
   */
  async load(id: string, tab: Tab, revision = '', path = '', file = false, offset = 0) {
    const generation = ++this.generation;
    this.update({busy:true,error:'',cell:null,tree:null,blob:null,readme:null,issues:[],revision,path,history:null,historyOffset:offset});
    try {
      const cell = await this.service.cell(id);
      const selected = revision || (cell.refs['refs/heads/main'] ? 'refs/heads/main' : Object.keys(cell.refs).filter(ref=>ref.startsWith('refs/heads/')).sort()[0] || 'refs/heads/main');
      const patch: Partial<RepositoryState> = {cell,revision:selected};
      if (generation !== this.generation) return;
      this.update(patch);
      if (tab === 'issues') patch.issues = await this.service.issues(id);
      if (tab === 'history') patch.history = await this.service.history(id,selected,offset);
      if (tab === 'code') {
        if (file) patch.blob = await this.service.blob(id,selected,path);
        else {
          const tree = await this.service.tree(id,selected,path); patch.tree = tree;
          const readme = tree.entries.find(entry=>entry.kind==='blob' && entry.name.toLowerCase()==='readme.md');
          if (readme && tree.revision) {
            try { patch.readme = await this.service.blob(id,tree.revision,readme.path); }
            catch (error) { patch.error = `README unavailable: ${error instanceof Error ? error.message : 'Request failed'}`; }
          }
        }
      }
      if (generation === this.generation) this.update(patch);
    } catch (error) { if (generation === this.generation) this.update({error:error instanceof Error ? error.message : 'Repository unavailable.'}); }
    finally { if (generation === this.generation) this.update({busy:false}); }
  }
}
