export interface Cell { id: string; name: string; owner: string; version: string; refs: Record<string, string>; members: Record<string, string> }
export interface Issue { id: string; title: string; body: string; closed: boolean }
export interface Peer { id: string; url: string; public_key: string }
export interface Status { identity: { id: string; name: string; email: string }; frame: { id: string; active: boolean }; cells: number; capabilities: string[] }
export interface AdminService {
  setToken(token: string): void;
  status(): Promise<Status>;
  cells(): Promise<Cell[]>;
  peers(): Promise<Peer[]>;
  createCell(name: string): Promise<Cell>;
  cell(id: string): Promise<Cell>;
  issues(id: string): Promise<Issue[]>;
  createIssue(id: string, title: string, body: string): Promise<Issue>;
  createPeer(peer: Peer): Promise<Peer>;
}
