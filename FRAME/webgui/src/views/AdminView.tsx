import { useEffect, useState, useSyncExternalStore } from 'react';
import type { AdminPresenter } from '../presenter/AdminPresenter';
import { Link } from 'react-router-dom';
import { Brand } from './Brand';
import { CellSignals } from './CellSignals';
import { PeerPanel } from './PeerPanel';

export function AdminView({ presenter: p, origin: _origin }: { presenter: AdminPresenter; origin: string }) {
  const state = useSyncExternalStore(p.subscribe, () => p.state, () => p.state);
  useEffect(() => { void p.connect(); }, [p]);
  const [name, setName] = useState('');
  const [creating, setCreating] = useState(false);
  const [filter, setFilter] = useState('');
  const [sort, setSort] = useState('asc');
  const repositories = state.cells
    .filter(cell => cell.name.toLowerCase().includes(filter.trim().toLowerCase()))
    .slice()
    .sort((a, b) => (sort === 'asc' ? 1 : -1) * a.name.localeCompare(b.name));
  return <div className="shell">
    <header className="masthead">
      <Brand />
      <span className="workspace-label">Your local workspace <span className="workspace-dot" aria-hidden="true" /></span>
    </header>
    <main>
      <section className="intro">
        <p className="eyebrow">YOUR WORK, WITH YOU</p>
        <h1>Room to build.<br /><span>Your CELLs, connected.</span></h1>
        <p className="muted">A home for your code and the people you build with. Managed by your FRAME, shared with your peers.</p>
      </section>
      {state.error && <div className="notice error" role="alert">{state.error}</div>}
      <div role="status" aria-live="polite" className="activity">{state.busy ? 'Working with your local frame…' : ''}</div>
      {!state.status ? <section className="panel login">
        <p className="eyebrow">CONNECT TO THIS FRAME</p>
        <h2>{state.error ? 'Frame unavailable' : 'Connecting to your frame…'}</h2>
        <p className="muted">An unlocked local FRAME connects automatically. If unavailable, run <code>comb cell list</code> in your terminal to unlock the daemon, then choose Retry. A locked managed FRAME closes its HTTP listener.</p>
        <button type="button" disabled={state.busy} onClick={() => { void p.connect(); }}>Retry</button>
        <p className="fine">Use only on a trusted local machine. Closing this page does not lock the daemon.</p>
      </section> : <>
        <section className="identity panel">
          <div>
            <p className="eyebrow">LOCAL IDENTITY</p>
            <h2>{state.status.identity.name}</h2>
            <p className="muted">{state.status.identity.email}</p>
            <code>{state.status.identity.id}</code>
          </div>
          <div className="frame">
            <span className={`pill ${state.status.frame.active ? 'good' : ''}`}>{state.status.frame.active ? 'Frame active' : 'Frame inactive'}</span>
            <code>{state.status.frame.id}</code>
            <button type="button" className="secondary" disabled={state.busy} onClick={() => { void p.connect(); }}>Refresh</button>
          </div>
        </section>
        <div className="dashboard">
          <section className="panel repositories" aria-labelledby="repos-heading">
          <div className="section-heading">
            <div>
              <p className="eyebrow">THE WORKSPACE</p>
              <h2 id="repos-heading">Your CELLs <span className="count">{state.cells.length}</span></h2>
            </div>
            <button type="button" disabled={state.busy} onClick={() => setCreating(!creating)} aria-expanded={creating}>New CELL</button>
          </div>
          {creating && <form className="inset" onSubmit={async event => {
            event.preventDefault();
            if (await p.createCell(name)) { setName(''); setCreating(false); }
          }}>
            <label htmlFor="repo-name">CELL name</label>
            <input id="repo-name" required value={name} onChange={event => setName(event.target.value)} />
            <div className="actions">
              <button disabled={state.busy}>Create CELL</button>
              <button type="button" className="secondary" onClick={() => { setCreating(false); setName(''); }}>Cancel</button>
            </div>
          </form>}
          <div className="filter-toolbar">
            <div className="filter-field">
              <label htmlFor="repository-filter">Find a CELL</label>
              <input id="repository-filter" type="search" placeholder="Filter by name…" value={filter} onChange={event => setFilter(event.target.value)} />
            </div>
            <div>
              <label htmlFor="repository-sort">Sort by name</label>
              <select id="repository-sort" value={sort} onChange={event => setSort(event.target.value)}>
                <option value="asc">Name: A–Z</option>
                <option value="desc">Name: Z–A</option>
              </select>
            </div>
          </div>
          <p className="fine" role="status">{repositories.length} of {state.cells.length} CELLs</p>
          {!state.cells.length && <p className="empty">Your next project starts here. Create a CELL, then push your first commit using Git.</p>}
          {!!state.cells.length && !repositories.length && <p className="empty">No CELLs match this name. Try a different search.</p>}
          <ul className="repo-list">
            {repositories.map(cell => {
              return <li key={cell.id}>
                <Link className="repo-row" to={`/cells/${encodeURIComponent(cell.id)}`}>
                  <span className="cell-emblem" aria-hidden="true">{cell.name.slice(0, 1).toUpperCase()}</span>
                  <div className="cell-card-body"><strong>{cell.name}</strong><CellSignals cell={cell} /></div>
                  <span className="cell-arrow" aria-hidden="true">↗</span>
                </Link>
              </li>;
            })}
          </ul>
          </section>
          <aside className="sidebar">
            <section className="panel">
              <p className="eyebrow">FRAME CAPABILITIES</p>
              <h2>Reported by daemon</h2>
              <div className="tags">
                {state.status.capabilities.length
                  ? state.status.capabilities.map(capability => <span className="pill" key={capability}>{capability}</span>)
                  : <p className="muted">None reported.</p>}
              </div>
            </section>
            <section className="panel connection-panel" aria-labelledby="connection-heading">
              <p className="eyebrow">THE CONNECTIONS</p>
              <h2 id="connection-heading">Work travels with peers.</h2>
              <p className="peer-total">{state.peers.length}<span>configured {state.peers.length === 1 ? 'peer' : 'peers'}</span></p>
              <p className="muted">Your FRAME exchanges CELL updates with configured peers when synchronization runs and they are reachable.</p>
              <a href="#peer-configuration" onClick={event => {
                const details = event.currentTarget.ownerDocument.getElementById('peer-configuration') as HTMLDetailsElement | null;
                if (details) details.open = true;
              }}>Manage peers <span aria-hidden="true">↗</span></a>
              <p className="fine">Live connectivity and last sync time are not reported by this FRAME.</p>
            </section>
          </aside>
        </div>
        <details id="peer-configuration" className="peer-configuration">
          <summary>Peer configuration <span className="count">{state.peers.length}</span></summary>
          <PeerPanel presenter={p} peers={state.peers} busy={state.busy} />
        </details>
      </>}
    </main><footer><span className="footer-brand">comb / Keep building.</span><span>Local workspace · prototype</span></footer>
  </div>;
}
