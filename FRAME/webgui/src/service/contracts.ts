/** JSON DTOs and injected service boundary shared by presenters and HTTP transport.
 * These types describe server responses, not runtime validation or authorization.
 */
/** Repository summary/detail: refs map full ref names to object IDs; members map
 * identity IDs to roles. slug names HTTP Git remotes; ssh_remote is server-configured.
 */
export interface Cell { id: string; name: string; slug: string; owner: string; version: string; refs: Record<string, string>; members: Record<string, string>; ssh_remote?: string | null }
/** Plain-text issue; the current API exposes listing/creation, not editing or closing. */
export interface Issue { id: string; title: string; body: string; closed: boolean }
/** Configured FRAME endpoint and public key, not evidence of reachability or trust. */
export interface Peer { id: string; url: string; public_key: string }
/** Unlocked daemon identity, FRAME activation, repository count, and advertised capabilities. */
export interface Status { identity: { id: string; name: string; email: string }; frame: { id: string; active: boolean }; cells: number; capabilities: string[] }
/** Committed path entry; symlinks/submodules are displayed but never followed by the UI. */
export interface TreeEntry { name: string; path: string; kind: 'tree' | 'blob' | 'symlink' | 'submodule'; size: number | null }
/** Directory at a resolved commit; null revision represents a repository without commits. */
export interface Tree { revision: string | null; path: string; entries: TreeEntry[] }
/** Bounded file preview. size is bytes; null content, binary, and truncated require
 * explicit unavailable states rather than attempting to render partial/binary data.
 */
export interface Blob { revision: string; path: string; size: number; content: string | null; binary: boolean; truncated: boolean }
/** Exported identity/FRAME JSON; cryptographic/domain validation belongs to the backend. */
export type Profile = Record<string, unknown>;
/** Grantable member roles; owner authority is not offered as a form choice. */
export type Role = 'read' | 'write';
/** Immutable commit metadata; parent count distinguishes merge commits for display. */
export interface Commit { id: string; parents: string[]; author: string; authored_at: string; subject: string }
/** Commit page pinned by resolved revision; next_offset is nullable, not a page number. */
export interface History { revision: string | null; commits: Commit[]; has_more: boolean; next_offset: number | null }
/** Async management boundary. IDs identify CELLs; revision/path inputs are validated
 * by the server. Rejections become presenter errors; successful mutations return
 * authoritative server state, not client-side optimistic substitutes.
 */
export interface AdminService {
  /** Read at most one history page starting at a nonnegative commit offset. */
  history(id: string, revision: string, offset: number): Promise<History>;
  /** List a repository-relative committed directory at a visible revision. */
  tree(id: string, revision: string, path: string): Promise<Tree>;
  /** Read a bounded committed blob preview. */
  blob(id: string, revision: string, path: string): Promise<Blob>;
  /** Rename and return effective metadata, including the updated Git slug. */
  renameCell(id: string, name: string): Promise<Cell>;
  /** Delete locally only, requiring the exact current repository name. */
  deleteCell(id: string, confirmation: string): Promise<{ deleted: string }>;
  /** Grant membership using an exported identity profile and read/write role. */
  grantMember(id: string, profile: Profile, role: Role): Promise<Cell>;
  /** Register an exported FRAME profile, passed as the request body itself. */
  registerFrame(id: string, profile: Profile): Promise<Cell>;
  /** Revoke the specified member identity, subject to backend ownership checks. */
  revokeMember(id: string, identityId: string): Promise<Cell>;
  /** Export the server-provided encrypted snapshot without decoding its schema. */
  backup(id: string): Promise<unknown>;
  /** Read active identity and daemon capabilities. */
  status(): Promise<Status>;
  /** List repositories held by this FRAME. */
  cells(): Promise<Cell[]>;
  /** List configured peer records. */
  peers(): Promise<Peer[]>;
  /** Create a named repository and return its server-assigned identity. */
  createCell(name: string): Promise<Cell>;
  /** Read repository metadata by stable ID. */
  cell(id: string): Promise<Cell>;
  /** List issues for one repository. */
  issues(id: string): Promise<Issue[]>;
  /** Create an issue with a title and plain-text body. */
  createIssue(id: string, title: string, body: string): Promise<Issue>;
  /** Save peer configuration without asserting a successful connection. */
  createPeer(peer: Peer): Promise<Peer>;
}
