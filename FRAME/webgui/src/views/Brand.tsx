/** Shared COMB wordmark, drawn locally so it works offline. */
export function Brand() {
  return <a className="brand" href="/" aria-label="COMB home">
    <svg className="comb-mark" viewBox="0 0 40 40" fill="none" aria-hidden="true">
      <path d="M20 3 35 11.5v17L20 37 5 28.5v-17Z" stroke="currentColor" strokeWidth="2.5" />
      <path d="M12 16v9m8-14v18m8-13v9" stroke="currentColor" strokeWidth="3" strokeLinecap="round" />
    </svg>
    <span>comb<small>A WORKSPACE, CONNECTED</small></span>
  </a>;
}
