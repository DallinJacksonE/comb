import { useState } from 'react';
import { Link } from 'react-router-dom';
import type { RepositoryState } from '../presenter/RepositoryPresenter';
import type { Cell } from '../service/contracts';

/** Branches reflect accepted CELL refs, never private FRAME bookkeeping refs. */
export function BranchesPanel({ cell }: { state: RepositoryState; cell: Cell }) {
  const [query, setQuery] = useState('');
  const branches = Object.entries(cell.refs)
    .filter(([ref]) => ref.startsWith('refs/heads/'))
    .sort(([a], [b]) => a.localeCompare(b));
  const visible = branches.filter(([ref]) => ref.slice('refs/heads/'.length).toLowerCase().includes(query.toLowerCase()));
  const base = `/cells/${encodeURIComponent(cell.id)}`;
  return <section aria-label="Repository branches">
    <div className="section-heading"><h2>Branches <span className="count">{branches.length}</span></h2></div>
    <label htmlFor="branch-search">Find a branch</label>
    <input id="branch-search" type="search" value={query} onChange={event => setQuery(event.target.value)} placeholder="Filter branches…" />
    <ul className="file-list">
      {visible.map(([ref, tip]) => {
        const search = new URLSearchParams({ revision: ref }).toString();
        return <li key={ref}>
          <div><Link to={`${base}?${search}`}><strong>{ref.slice('refs/heads/'.length)}</strong></Link><p className="fine"><code>{tip}</code></p></div>
          <div className="actions"><Link className="button secondary" to={`${base}?${search}`}>Browse code</Link><Link className="button secondary" to={`${base}/history?${search}`}>History</Link></div>
        </li>;
      })}
    </ul>
    {!visible.length && <p className="empty">{branches.length ? 'No branches match your search.' : 'No branches yet. Push a branch using Git.'}</p>}
    <p className="fine">Create, push, and delete branches with your Git client. This page shows branches accepted by this CELL.</p>
  </section>;
}
