import { useState } from 'react';
import type { Cell } from '../service/contracts';

/** Keep transport credentials and client-side key passphrases visibly distinct. */
export function RepositoryRemotes({ cell, origin }: { cell: Cell; origin: string }) {
  const [message, setMessage] = useState('');
  const httpRemote = `${origin}/git/${cell.slug}.git`;
  async function copy(value: string, transport: string) {
    setMessage('');
    try {
      if (!navigator.clipboard?.writeText) throw new Error('Clipboard unavailable');
      await navigator.clipboard.writeText(value);
      setMessage(`Copied ${transport} URL.`);
    } catch {
      setMessage('Could not copy. Please select the URL and copy it manually.');
    }
  }
  return <details className="clone-menu">
    <summary>Get the code ↗</summary>
    <section className="clone-content" aria-label="Repository remotes">
    <h2>Work with this CELL</h2>
    {cell.ssh_remote ? <>
      <label htmlFor="ssh-remote">SSH remote URL</label>
      <div className="remote-row">
        <input id="ssh-remote" readOnly value={cell.ssh_remote} onFocus={event => event.target.select()} />
        <button type="button" className="secondary" onClick={() => { void copy(cell.ssh_remote!, 'SSH'); }}>Copy SSH URL</button>
      </div>
      <p className="fine">The COMB SSH alias selects your FRAME key automatically. OpenSSH asks for its optional key passphrase, or uses ssh-agent. This is not your FRAME unlock password.</p>
    </> : <p className="fine">SSH is not configured for this FRAME. Run <code>comb ssh setup</code>, then restart and unlock the FRAME.</p>}
    <label htmlFor="git-remote">Git remote URL (HTTP)</label>
    <div className="remote-row">
      <input id="git-remote" readOnly value={httpRemote} onFocus={event => event.target.select()} />
      <button type="button" className="secondary" onClick={() => { void copy(httpRemote, 'HTTP'); }}>Copy HTTP URL</button>
    </div>
    <p className="fine">HTTP still uses your management token as the Git password. Never embed credentials in a remote URL.</p>
    <p className="fine" role="status" aria-live="polite">{message}</p>
    </section>
  </details>;
}
