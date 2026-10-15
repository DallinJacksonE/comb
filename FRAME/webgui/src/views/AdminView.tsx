import { useState, useSyncExternalStore } from 'react';
import type { AdminPresenter } from '../presenter/AdminPresenter';
import { CellDetail } from './CellDetail';
import { PeerPanel } from './PeerPanel';

export function AdminView({ presenter: p, origin }: { presenter: AdminPresenter; origin: string }) {
  const state = useSyncExternalStore(p.subscribe, () => p.state, () => p.state);
  const [token, setToken] = useState('');
  const [name, setName] = useState('');
  const [creating, setCreating] = useState(false);
  return <div className="shell">
    <header className="masthead"><a className="brand" href="/" aria-label="CELL GUARD home"><span className="mark" aria-hidden="true">⬡</span><span>CELL GUARD<small>LOCAL FRAME CONSOLE</small></span></a><span className="pill">Local-first · prototype</span></header>
    <main>
      <section className="intro"><p className="eyebrow">YOUR IDENTITY. YOUR REPOSITORIES.</p><h1>A home for your cells.</h1><p className="muted">Manage this frame with your existing local identity. No central account required.</p></section>
      {state.error && <div className="notice error" role="alert">{state.error}</div>}
      <div role="status" aria-live="polite" className="activity">{state.busy ? 'Working with your local frame…' : ''}</div>
      {!state.status ? <section className="panel login"><p className="eyebrow">CONNECT TO THIS FRAME</p><h2>Welcome back.</h2><p className="muted">Enter the management token issued by your local daemon. It stays in memory and is cleared when you disconnect or reload.</p>
        <form onSubmit={async event => { event.preventDefault(); if (await p.connect(token)) setToken(''); }}>
          <label htmlFor="token">Local management token</label><input id="token" type="password" autoComplete="off" spellCheck={false} required value={token} onChange={e => setToken(e.target.value)} />
          <button disabled={state.busy}>Connect to frame</button>
        </form><p className="fine">Prototype management access. Use only on a trusted local machine.</p>
      </section> : <>
        <section className="identity panel"><div><p className="eyebrow">LOCAL IDENTITY</p><h2>{state.status.identity.name}</h2><p className="muted">{state.status.identity.email}</p><code>{state.status.identity.id}</code></div><div className="frame"><span className={`pill ${state.status.frame.active ? 'good' : ''}`}>{state.status.frame.active ? 'Frame active' : 'Frame inactive'}</span><code>{state.status.frame.id}</code><button type="button" className="secondary" disabled={state.busy} onClick={() => { p.disconnect(); setCreating(false); setName(''); }}>Disconnect</button></div></section>
        <div className="dashboard"><section className="panel repositories" aria-labelledby="repos-heading"><div className="section-heading"><div><p className="eyebrow">CELLS / GIT REPOSITORIES</p><h2 id="repos-heading">Repositories <span className="count">{state.cells.length}</span></h2></div><button type="button" disabled={state.busy} onClick={() => setCreating(!creating)} aria-expanded={creating}>New repository</button></div>
          {creating && <form className="inset" onSubmit={async e => { e.preventDefault(); if (await p.createCell(name)) { setName(''); setCreating(false); } }}><label htmlFor="repo-name">Repository name</label><input id="repo-name" required value={name} onChange={e => setName(e.target.value)} /><div className="actions"><button disabled={state.busy}>Create repository</button><button type="button" className="secondary" onClick={() => { setCreating(false); setName(''); }}>Cancel</button></div></form>}
          {!state.cells.length && <p className="empty">No cells yet. Create your first repository to get started.</p>}
          <ul className="repo-list">{state.cells.map(cell => <li key={cell.id}><button type="button" className="repo-row secondary" disabled={state.busy} aria-expanded={state.detail?.id === cell.id} onClick={() => { setCreating(false); void p.openCell(cell.id); }}><span><strong>{cell.name}</strong><small>{cell.id}</small></span><span className="muted">{state.detail?.id === cell.id ? 'Close −' : 'Explore +'}</span></button>{state.detail?.id === cell.id && <CellDetail key={cell.id} cell={state.detail} issues={state.issues} presenter={p} origin={origin} busy={state.busy} />}</li>)}</ul>
        </section><aside className="sidebar"><section className="panel"><p className="eyebrow">FRAME CAPABILITIES</p><h2>Reported by daemon</h2><div className="tags">{state.status.capabilities.length ? state.status.capabilities.map(c => <span className="pill" key={c}>{c}</span>) : <p className="muted">None reported.</p>}</div></section><section className="panel limits"><p className="eyebrow">PROTOTYPE BOUNDARIES</p><h2>Not available</h2><p>Code browsing, pull requests, issue editing, member changes, and federation controls are not exposed by this API.</p><p>Registered peers are configuration records, not proof of a live or trusted connection.</p></section></aside></div>
        <PeerPanel presenter={p} peers={state.peers} busy={state.busy} />
      </>}
    </main><footer>CELL GUARD <span>Local management · prototype, not production security</span></footer>
  </div>;
}
