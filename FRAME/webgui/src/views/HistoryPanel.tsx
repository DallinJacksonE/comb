import { Link, useSearchParams } from 'react-router-dom';
import type { RepositoryState } from '../presenter/RepositoryPresenter';
import type { Cell } from '../service/contracts';

/** History is read-only; every source link targets an immutable commit. */
export function HistoryPanel({ state, cell }: { state: RepositoryState; cell: Cell }) {
  const [, setParams] = useSearchParams();
  const history = state.history;
  const base = `/cells/${encodeURIComponent(cell.id)}`;
  const pageLink = (offset: number) => `?${new URLSearchParams({
    revision: history?.revision || state.revision, offset: String(offset),
  })}`;
  return <section aria-label="Commit history">
    <div className="section-heading">
      <h2>Commit history</h2>
      <div>
        <label htmlFor="history-branch">Revision</label>{' '}
        <select id="history-branch" value={state.revision} onChange={event => setParams({ revision: event.target.value })}>
          {[...new Set([state.revision, ...Object.keys(cell.refs).filter(ref => ref.startsWith('refs/heads/'))])].filter(Boolean).map(ref =>
            <option key={ref} value={ref}>{ref.replace('refs/heads/', '')}</option>)}
        </select>
      </div>
    </div>
    {history && !history.commits.length && <p className="empty">No commits yet. Push a commit using Git.</p>}
    <ul className="commit-list file-list">
      {history?.commits.map(commit => <li key={commit.id}>
        <div>
          <strong>{commit.subject || '(no commit message)'}</strong>
          <p className="fine">{commit.author} committed <time dateTime={commit.authored_at}>{commit.authored_at}</time></p>
          {commit.parents.length > 1 && <span className="pill">Merge commit</span>}
        </div>
        <div className="actions">
          <code title={commit.id}>{commit.id.slice(0, 10)}</code>
          <Link className="button secondary" to={`${base}?${new URLSearchParams({ revision: commit.id })}`}>Browse files</Link>
        </div>
      </li>)}
    </ul>
    {history && <nav className="actions" aria-label="History pagination">
      {state.historyOffset > 0 && <Link className="button secondary" to={pageLink(Math.max(0, state.historyOffset - 30))}>Newer commits</Link>}
      {history.has_more && history.next_offset !== null && <Link className="button secondary" to={pageLink(history.next_offset)}>Older commits</Link>}
    </nav>}
  </section>;
}
