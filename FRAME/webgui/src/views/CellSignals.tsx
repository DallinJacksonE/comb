import type { Cell } from '../service/contracts';

/** Describe only observable CELL state, without implying peer reachability. */
export function CellSignals({ cell }: { cell: Cell }) {
  const refs = Object.keys(cell.refs);
  const divergent = refs.filter(ref => ref.startsWith('refs/comb/divergent/')).length;
  const branches = refs.filter(ref => ref.startsWith('refs/heads/')).length;
  const members = Object.keys(cell.members).length;
  return <div className="cell-signals" aria-label="CELL summary">
    <span>{branches} {branches === 1 ? 'branch' : 'branches'}</span>
    <span>{members} {members === 1 ? 'member' : 'members'}</span>
    {divergent > 0 && <span className="reconciliation">{divergent} divergent {divergent === 1 ? 'tip' : 'tips'} · Reconciliation needed</span>}
  </div>;
}
