import { Brand } from './Brand';
import { useEffect, useRef, useState, useSyncExternalStore } from 'react';
import type { FormEvent, ReactNode } from 'react';
import type { BrowserSessionPresenter } from '../presenter/BrowserSessionPresenter';

export function BrowserSessionView({ presenter, children }: { presenter: BrowserSessionPresenter; children?: ReactNode }) {
  const state = useSyncExternalStore(presenter.subscribe, () => presenter.state);
  const [token, setToken] = useState('');
  const input = useRef<HTMLInputElement>(null);
  useEffect(() => { void presenter.load(); }, [presenter]);
  // Recheck when returning to a tab, including a page restored from browser history.
  useEffect(() => {
    const recheck = () => { void presenter.sessionExpired(); };
    const visible = () => { if (document.visibilityState === 'visible') recheck(); };
    window.addEventListener('pageshow', recheck);
    window.addEventListener('focus', recheck);
    document.addEventListener('visibilitychange', visible);
    return () => {
      window.removeEventListener('pageshow', recheck);
      window.removeEventListener('focus', recheck);
      document.removeEventListener('visibilitychange', visible);
    };
  }, [presenter]);
  async function login(event: FormEvent) {
    event.preventDefault();
    const field = input.current;
    if (await presenter.login(token)) {
      if (field) field.value = '';
      setToken('');
    }
  }

  if (state.session?.mode === 'local') return <>{children}</>;
  if (state.session?.mode === 'remote' && state.session.authenticated) {
    return <>
      <aside className="browser-session-toolbar" aria-label="Remote admin session">
        <span>Remote admin · FRAME <code>{state.session.frame_id ?? 'unavailable'}</code></span>
        <details className="browser-session-profile">
          <summary>Signed FRAME profile</summary>
          <p>Compare this signed profile JSON independently with an out-of-band trusted FRAME profile. This UI does not prove identity or provide certificate pinning.</p>
          <pre>{JSON.stringify(state.session.profile, null, 2)}</pre>
        </details>
        <button className="secondary" onClick={() => { void presenter.logout(); }}>Sign out</button>
      </aside>
      {children}
    </>;
  }
  return <main className="browser-session-gate">
    <section className="browser-session-card" aria-labelledby="browser-session-title">
      <Brand />
      <p className="eyebrow">COMB / FRAME MANAGEMENT</p>
      <h1 id="browser-session-title">{state.session ? 'Sign in to your FRAME' : 'Checking browser session'}</h1>
      {state.error && <p role="alert" className="notice error">{state.error}</p>}
      {state.busy ? <p role="status">Checking secure browser access…</p> : state.session?.mode === 'remote' ? <>
        <p>Owner-only remote administration. Enter your remote admin management token to continue.</p>
        <p className="fine" id="browser-token-help">This is NOT your FRAME unlock password or SSH password. Use a trusted HTTPS service URL and compare the signed FRAME profile independently after signing in.</p>
        <form onSubmit={login}>
          <label htmlFor="browser-token">Remote admin management token</label>
          <input ref={input} id="browser-token" type="password" autoComplete="off" spellCheck={false} value={token} onChange={event => setToken(event.target.value)} aria-describedby="browser-token-help" required />
          <button type="submit" disabled={!token.trim()}>Sign in</button>
        </form>
      </> : <>
        <p className="fine">If this is your local daemon, start or unlock your FRAME locally, then retry. Remote access requires the configured HTTPS service to be available.</p>
        <button onClick={() => { void presenter.load(); }}>Retry session check</button>
      </>}
    </section>
  </main>;
}
