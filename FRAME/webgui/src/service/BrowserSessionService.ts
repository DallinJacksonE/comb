/** Browser-session discovery and ephemeral management-token exchange, separate from unlock. */
/** Server-reported access boundary; local mode does not require a remote login cookie. */
export interface BrowserSession {
  /** Local automatic access or explicitly configured remote HTTPS administration. */
  mode: 'local' | 'remote';
  /** Whether remote administration is authenticated; not a daemon unlock flag. */
  authenticated: boolean;
  /** Optional FRAME identity and signed profile for independent out-of-band comparison. */
  frame_id: string | null;
  profile: unknown | null;
}

/** Injectable session API; tokens are arguments only, never persistent client state. */
export interface BrowserSessionService {
  /** Discover access mode and current cookie-session metadata. */
  load(): Promise<BrowserSession>;
  /** Exchange a management token for the server's browser cookie session. */
  login(token: string): Promise<BrowserSession>;
  /** Invalidate the current remote session. */
  logout(): Promise<BrowserSession>;
}

/** Relative, marked, no-store requests; browser-managed same-origin cookies carry access. */
export class HttpBrowserSessionService implements BrowserSessionService {
  /** Inject fetch for tests; default to the browser's native transport. */
  constructor(private transport: typeof fetch = fetch) {}

  /** Send JSON only for token exchange; errors omit server text to avoid reflecting secrets. */
  private async request(method: string, token?: string): Promise<BrowserSession> {
    const transport = this.transport;
    const response = await transport('/api/browser/session', {
      method,
      credentials: 'same-origin',
      cache: 'no-store',
      headers: { 'X-Comb-Webgui': '1', ...(token === undefined ? {} : { 'Content-Type': 'application/json' }) },
      body: token === undefined ? undefined : JSON.stringify({ token }),
    });
    if (!response.ok) throw new Error(`Session request failed (HTTP ${response.status}).`);
    return response.json() as Promise<BrowserSession>;
  }

  /** Read the session without sending a token. */
  load() { return this.request('GET'); }
  /** POST the original token in JSON, never in a URL or authorization header. */
  login(token: string) { return this.request('POST', token); }
  /** DELETE the current cookie session without a body. */
  logout() { return this.request('DELETE'); }
}
