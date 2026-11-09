/** Fail-closed session transitions shared by the login gate and unauthorized handler. */
import type { BrowserSession, BrowserSessionService } from '../service/BrowserSessionService';

/** Gate snapshot; null session hides private children while checking or after failure. */
export interface BrowserSessionState {
  /** Server access mode and authentication metadata, never the submitted token. */
  session: BrowserSession | null;
  busy: boolean;
  error: string;
}

/** Keep only the latest session request authoritative and never retain login tokens. */
export class BrowserSessionPresenter {
  /** Observable snapshot consumed by useSyncExternalStore. */
  state: BrowserSessionState = { session: null, busy: false, error: '' };
  /** Incremented before every transition so late login/load responses cannot reopen the gate. */
  private generation = 0;
  private listeners = new Set<() => void>();
  /** Inject session transport independently of React and browser globals. */
  constructor(private service: BrowserSessionService) {}
  /** Observe state changes and return an unsubscribe callback. */
  subscribe = (listener: () => void) => {
    this.listeners.add(listener);
    return () => { this.listeners.delete(listener); };
  };
  /** Publish a new snapshot to all current listeners. */
  private update(patch: Partial<BrowserSessionState>) {
    this.state = { ...this.state, ...patch };
    this.listeners.forEach(listener => listener());
  }
  /** Hide private state immediately; ignore stale results and redact transport error details. */
  private async run(action: () => Promise<BrowserSession>) {
    const generation = ++this.generation;
    this.update({ session: null, busy: true, error: '' });
    try {
      const session = await action();
      if (generation !== this.generation) return false;
      this.update({ session, busy: false });
      return true;
    } catch {
      if (generation !== this.generation) return false;
      this.update({ busy: false, error: 'Unable to update browser session. Check your connection and management token, then retry.' });
      return false;
    }
  }
  /** Recheck after HTTP 401, focus, or history restoration instead of trusting cached access. */
  sessionExpired() { return this.load(); }
  /** Discover local automatic access or the current remote cookie session. */
  load() { return this.run(() => this.service.load()); }
  /** Reject blank tokens locally; submit the original token without storing it in state. */
  login(token: string) {
    if (!token.trim()) {
      this.update({ error: 'A remote admin management token is required.' });
      return Promise.resolve(false);
    }
    return this.run(() => this.service.login(token));
  }
  /** Hide the workspace before asking the server to invalidate the remote cookie. */
  logout() { return this.run(() => this.service.logout()); }
}
