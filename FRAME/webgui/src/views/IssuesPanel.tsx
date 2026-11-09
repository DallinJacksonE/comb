import { useState } from 'react';
import type { RepositoryPresenter, RepositoryState } from '../presenter/RepositoryPresenter';
export function IssuesPanel({presenter:p,state}: {presenter:RepositoryPresenter;state:RepositoryState}) {
  const [title, setTitle] = useState('');
  const [body, setBody] = useState('');
  const [search, setSearch] = useState('');
  const [status, setStatus] = useState('all');
  const query = search.trim().toLowerCase();
  const issues = state.issues.filter(issue =>
    (status === 'all' || issue.closed === (status === 'closed')) &&
    `${issue.title} ${issue.body} ${issue.id}`.toLowerCase().includes(query)
  );
  const openCount = state.issues.filter(issue => !issue.closed).length;
  return <section aria-label="Repository issues">
    <div className="section-heading">
      <h2>Issues <span className="count">{state.issues.length}</span></h2>
      <span className="muted">{openCount} open · {state.issues.length - openCount} closed</span>
    </div>
    <div className="filter-toolbar">
      <div className="filter-field">
        <label htmlFor="issue-search">Search issues</label>
        <input id="issue-search" type="search" placeholder="Search titles and descriptions…" value={search} onChange={event => setSearch(event.target.value)} />
      </div>
      <div>
        <label htmlFor="issue-status">Status</label>
        <select id="issue-status" value={status} onChange={event => setStatus(event.target.value)}>
          <option value="all">All issues</option>
          <option value="open">Open</option>
          <option value="closed">Closed</option>
        </select>
      </div>
    </div>
    {!state.issues.length && <p className="empty">No issues yet.</p>}
    {!!state.issues.length && !issues.length && <p className="empty">No issues match your filters.</p>}
    <ul className="issue-list">
      {issues.map(issue => <li key={issue.id}>
        <details>
          <summary><span className={`pill ${issue.closed ? '' : 'good'}`}>{issue.closed ? 'Closed' : 'Open'}</span><strong>{issue.title}</strong></summary>
          <div className="issue-details">
            <p className="body-text">{issue.body || 'No description provided.'}</p>
            <small className="muted">{issue.id}</small>
          </div>
        </details>
      </li>)}
    </ul>
    <form className="issue-create" onSubmit={async event => {
      event.preventDefault();
      if (await p.createIssue(title, body)) { setTitle(''); setBody(''); }
    }}>
      <h3>New issue</h3>
      <p className="fine">Create an issue in this repository. Editing and closing issues are not available in this API.</p>
      <label htmlFor="issue-title">Title</label>
      <input id="issue-title" required value={title} onChange={event => setTitle(event.target.value)} />
      <label htmlFor="issue-body">Description</label>
      <textarea id="issue-body" rows={4} value={body} onChange={event => setBody(event.target.value)} />
      <button disabled={state.busy}>Create issue</button>
    </form>
  </section>;
}
