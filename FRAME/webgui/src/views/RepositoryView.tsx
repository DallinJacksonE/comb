import { useEffect, useSyncExternalStore } from 'react';
import { Link, NavLink, useParams, useSearchParams } from 'react-router-dom';
import type { RepositoryPresenter, Tab } from '../presenter/RepositoryPresenter';
import { Brand } from './Brand';
import { CellSignals } from './CellSignals';
import { CodePanel } from './CodePanel';
import { IssuesPanel } from './IssuesPanel';
import { SettingsPanel } from './SettingsPanel';
import { RepositoryRemotes } from './RepositoryRemotes';
import { HistoryPanel } from './HistoryPanel';
import { BranchesPanel } from './BranchesPanel';
export function RepositoryView({presenter:p,origin,tab}: {presenter:RepositoryPresenter;origin:string;tab:Tab}) {
  const { id = '' } = useParams();
  const [params] = useSearchParams();
  const revision = params.get('revision') || '';
  const path = params.get('path') || '';
  const file = params.get('file') === '1';
  const rawOffset = params.get('offset') || '0';
  const offset = /^\d+$/.test(rawOffset) && Number(rawOffset) <= 10000 ? Number(rawOffset) : 0;
  const state = useSyncExternalStore(p.subscribe, () => p.state, () => p.state);
  const load = () => p.load(id, tab, revision, path, file, offset);
  useEffect(() => { void p.load(id, tab, revision, path, file, offset); }, [p, id, tab, revision, path, file, offset]);
  const cell = state.cell;
  const base = `/cells/${encodeURIComponent(id)}`;
  return <div className="shell">
    <header className="masthead">
      <Brand />
      <Link to="/">All CELLs</Link>
    </header>
    <main className="repository-page">
      <div className="repository-heading">
        <div>
          <p className="eyebrow">SHARED PROJECT · LOCAL WORKSPACE</p>
          <h1>{cell?.name || 'Your CELL'}</h1>
          {cell && <CellSignals cell={cell} />}
          {cell && <details className="repository-meta"><summary>CELL identity &amp; version</summary><dl className="metadata"><div><dt>CELL</dt><dd><code>{cell.id}</code></dd></div><div><dt>Owner</dt><dd><code>{cell.owner}</code></dd></div><div><dt>Version</dt><dd><code>{cell.version}</code></dd></div></dl></details>}
        </div>
        {cell && <RepositoryRemotes cell={cell} origin={origin} />}
      </div>
      <div className="cell-layout">
      <nav className="tabs" aria-label="Repository tabs">
        <p className="eyebrow">IN THIS CELL</p>
        <NavLink end to={base}>Code</NavLink>
        <NavLink to={`${base}/issues`}>Issues</NavLink>
        <NavLink to={`${base}/history`}>History</NavLink>
        <NavLink to={`${base}/branches`}>Branches</NavLink>
        <NavLink to={`${base}/settings`}>Settings</NavLink>
      </nav>
      <div className="cell-main">
      <div role="status" aria-live="polite" className="activity">{state.busy ? 'Loading repository…' : ''}</div>
      {state.error && <div className="notice error" role="alert">
        {state.error}
        <p>Repository or path unavailable? Check the branch/path. If this FRAME is unavailable, run <code>comb cell list</code> to unlock it.</p>
        <button className="secondary" disabled={state.busy} onClick={() => { void load(); }}>Retry</button>
      </div>}
      {cell && <div className={`panel repository-content ${tab === 'code' ? 'code-content' : ''}`}>
        {tab === 'code' && <CodePanel state={state} cell={cell} />}
        {tab === 'issues' && <IssuesPanel key={cell.id} presenter={p} state={state} />}
        {tab === 'history' && <HistoryPanel state={state} cell={cell} />}
        {tab === 'branches' && <BranchesPanel state={state} cell={cell} />}
        {tab === 'settings' && <SettingsPanel key={cell.id} presenter={p} cell={cell} busy={state.busy} />}
      </div>}
      </div></div>
    </main>
    <footer><span className="footer-brand">comb / Keep building.</span><span>Local workspace · prototype</span></footer>
  </div>;
}
