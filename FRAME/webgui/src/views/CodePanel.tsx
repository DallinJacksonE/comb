import { Link, useSearchParams } from 'react-router-dom';
import type { Blob, Cell } from '../service/contracts';
import type { RepositoryState } from '../presenter/RepositoryPresenter';
import { SafeMarkdown } from './SafeMarkdown';
export function BlobContent({blob,markdown=false}: {blob: Blob; markdown?: boolean}) {
  if (blob.binary) return <p className="empty">Binary file — preview unavailable.</p>;
  if (blob.truncated) return <p className="empty">File too large to preview.</p>;
  if (blob.content === null) return <p className="empty">Content unavailable.</p>;
  if (!blob.content) return <p className="empty">Empty file.</p>;
  return markdown ? <SafeMarkdown content={blob.content}/> : <pre className="source"><code>{blob.content}</code></pre>;
}
export function CodePanel({state,cell}: {state: RepositoryState;cell:Cell}) {
  const [, setParams] = useSearchParams();
  const href = (path: string, file = false) => `?${new URLSearchParams({ revision: state.revision, path, ...(file ? { file: '1' } : {}) })}`;
  const parts = state.path.split('/').filter(Boolean);
  const branches = [...new Set([state.revision, ...Object.keys(cell.refs).filter(ref => ref.startsWith('refs/heads/'))])].filter(Boolean);
  return <section aria-label="Repository code">
    <div className="code-intro"><div><p className="eyebrow">THE SOURCE</p><h2>Made here. Shared from here.</h2></div><p className="muted">Browse committed code. Fetch and push with your Git tools.</p></div>
    <div className="code-toolbar">
      <div className="branch-control">
        <label htmlFor="branch">Branch</label>
        <select id="branch" value={state.revision} onChange={event => setParams({ revision: event.target.value, path: '' })}>
          {branches.map(ref => <option key={ref} value={ref}>{ref.replace('refs/heads/', '')}</option>)}
        </select>
      </div>
      <nav className="breadcrumbs" aria-label="Code path">
        <Link to={href('')}>Root</Link>
        {parts.map((part, index) => <span key={index}> / <Link to={href(parts.slice(0, index + 1).join('/'), !!state.blob && index === parts.length - 1)}>{part}</Link></span>)}
      </nav>
    </div>
    {state.blob && <article className="file-browser blob-browser">
      <div className="file-browser-heading">
        <h2>{state.path}</h2>
        <Link to={href(parts.slice(0, -1).join('/'))}>↑ Parent directory</Link>
      </div>
      <BlobContent blob={state.blob} markdown={/\.md$/i.test(state.path)} />
    </article>}
    {state.tree && <>
      <div className="file-browser">
        <div className="file-browser-heading">
          <span>{state.path || 'Repository files'}</span>
          {state.tree.revision && <code title={state.tree.revision}>{state.tree.revision.slice(0, 10)}</code>}
        </div>
        {state.path && <div className="parent-directory"><Link to={href(parts.slice(0, -1).join('/'))}>↑ Parent directory</Link></div>}
        <ul className="file-list">
          {state.tree.entries.map(entry => <li key={entry.path}>
            {entry.kind === 'tree' || entry.kind === 'blob'
              ? <Link to={href(entry.path, entry.kind === 'blob')}><span aria-hidden="true" className="file-icon">{entry.kind === 'tree' ? '▸' : '≡'}</span>{entry.name}</Link>
              : <span>{entry.name} <small>({entry.kind} — preview disabled)</small></span>}
            <small className="muted">{entry.kind}{entry.size === null ? '' : ` · ${entry.size} bytes`}</small>
          </li>)}
        </ul>
        {!state.tree.entries.length && <p className="empty">{state.tree.revision === null ? 'No commits yet. Push a commit using Git.' : 'Empty directory.'}</p>}
      </div>
      {state.readme
        ? <article className="readme inset"><h2>README.md</h2><BlobContent blob={state.readme} markdown /></article>
        : state.tree.revision && <p className="fine">No README.md in this directory.</p>}
    </>}
  </section>;
}
