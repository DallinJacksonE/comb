import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import type { Cell, Role } from '../service/contracts';
import type { RepositoryPresenter } from '../presenter/RepositoryPresenter';
export function SettingsPanel({presenter:p,cell,busy}: {presenter:RepositoryPresenter;cell:Cell;busy:boolean}) {
  const navigate=useNavigate();
  const [name,setName]=useState(cell.name);
  const [confirmation,setConfirmation]=useState('');
  const [profile,setProfile]=useState('');
  const [frame,setFrame]=useState('');
  const [role,setRole]=useState<Role>('read');
  const [exported,setExported]=useState(false);
  return <div className="settings-grid">
    <section className="inset">
      <h2>Collaborators and access</h2>
      <p className="muted">Members are identified by their cryptographic identity, not a hosted account. The repository owner cannot be revoked here.</p>
      <ul className="file-list member-list">
        {Object.entries(cell.members).map(([id, memberRole]) => <li key={id}>
          <span><code>{id}</code> <span className="pill">{memberRole}</span></span>
          {id !== cell.owner && memberRole !== 'owner' && <button type="button" className="secondary" disabled={busy} onClick={() => { void p.revoke(id); }}>Revoke</button>}
        </li>)}
      </ul>
      {!Object.keys(cell.members).length && <p>No members reported.</p>}
      <form onSubmit={async event => {
        event.preventDefault();
        if (await p.grant(profile, role)) setProfile('');
      }}>
        <h3>Grant member</h3>
        <p className="fine">Ask your collaborator for their exported identity profile JSON and verify it through a trusted channel. Paste that profile below to grant access. There is no username lookup or invitation service.</p>
        <label htmlFor="member-profile">Member profile JSON</label>
        <textarea id="member-profile" required rows={5} value={profile} onChange={event => setProfile(event.target.value)} />
        <label htmlFor="member-role">Role</label>
        <select id="member-role" value={role} onChange={event => setRole(event.target.value as Role)}>
          <option value="read">Read</option>
          <option value="write">Write</option>
        </select>
        <button disabled={busy}>Grant member</button>
      </form>
    </section>
    <section className="inset">
      <form onSubmit={async event => {
        event.preventDefault();
        if (await p.registerFrame(frame)) setFrame('');
      }}>
        <h2>Register FRAME</h2>
        <label htmlFor="frame-profile">FRAME profile JSON</label>
        <textarea id="frame-profile" required rows={5} value={frame} onChange={event => setFrame(event.target.value)} />
        <button disabled={busy}>Register FRAME</button>
      </form>
    </section>
    <section className="inset">
      <h2>Encrypted backup</h2>
      <p>Export the encrypted snapshot returned by your local FRAME. Keep exported backups safe; deleting this repository will not remove them.</p>
      <button disabled={busy} type="button" onClick={async () => {
        setExported(false);
        const snapshot = await p.exportBackup();
        if (snapshot === false) return;
        const url = URL.createObjectURL(new Blob([JSON.stringify(snapshot, null, 2)], { type: 'application/json' }));
        const link = document.createElement('a');
        link.href = url;
        link.download = `${cell.slug}-backup.json`;
        document.body.append(link);
        link.click();
        link.remove();
        setTimeout(() => URL.revokeObjectURL(url), 1000);
        setExported(true);
      }}>Export encrypted backup</button>
      {exported && <p role="status">Encrypted snapshot download started.</p>}
    </section>
    <section className="inset">
      <form onSubmit={async event => {
        event.preventDefault();
        if (await p.rename(name)) { setName(p.state.cell!.name); setConfirmation(''); }
      }}>
        <h2>Rename repository</h2>
        <p>Identity and history stay unchanged. Renaming updates the name-based Git remote URL.</p>
        <label htmlFor="rename-name">Repository name</label>
        <input id="rename-name" required value={name} onChange={event => setName(event.target.value)} />
        <button disabled={busy}>Rename repository</button>
      </form>
    </section>
    <section className="inset danger-zone">
      <form onSubmit={async event => {
        event.preventDefault();
        if (await p.delete(confirmation)) navigate('/');
      }}>
        <h2>Delete local repository</h2>
        <p>Remove this repository only from this local FRAME. Other peers, independent worktrees, and exported backups are untouched. This is not distributed deletion.</p>
        <label htmlFor="delete-confirmation">Type the exact repository name: <strong>{cell.name}</strong></label>
        <input id="delete-confirmation" required autoComplete="off" value={confirmation} onChange={event => setConfirmation(event.target.value)} />
        <button disabled={busy || confirmation !== cell.name}>Delete local repository</button>
      </form>
    </section>
  </div>;
}
