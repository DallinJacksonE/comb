# CELL GUARD web GUI

React + TypeScript + Vite management UI for the FRAME daemon, with default local automatic access and optional authenticated HTTPS hosting. This is a prototype console, **not a production-security claim**. It uses your existing FRAME identity; it does not create central accounts. See [HTTPS hosting](../HTTPS.md) for direct TLS, development certificates, and reverse-proxy deployment.

## Run

Use a current Node.js LTS and npm. From `FRAME/webgui`:

```sh
npm install
npm test
npm run build
npm run dev
```

Start the FRAME backend separately on `localhost:7331`. Vite binds to **127.0.0.1** (normally port 5173) and proxies `/api` and `/git` to `http://localhost:7331`. If that port is occupied, use `npm run dev -- --port 17331 --strictPort`. Open the Vite URL printed in your terminal.

For the integrated daemon UI, build first and configure/run the backend to serve this directory's `dist/` at `/`. Production asset serving belongs to the backend; there is no extra Node production server here. `npm run preview` serves only built static assets and does not proxy API requests.

The UI discovers its access mode through `/api/browser/session`. It automatically connects to an **already unlocked local FRAME** without a management-token form. On the separate remote HTTPS listener it instead requires sign-in with the management token, exchanged for a bounded, expiring HttpOnly/Secure/SameSite=Strict cookie. It never submits the FRAME unlock password. Each API request uses a relative same-origin URL with `X-Comb-Webgui: 1`, `credentials: 'same-origin'`, and `cache: 'no-store'`; it sends no Bearer authorization. No secret is persisted in localStorage/sessionStorage or URLs. The marker alone is not authorization: the backend also verifies browser metadata and the appropriate Host/Origin boundary. The browser supplies `Sec-Fetch-Site: same-origin` and the Origin for writes; JavaScript does not forge these headers. Use the daemon-served UI for this security contract. A Vite proxy on a different port may fail the backend's Origin/Host checks for writes; do not weaken those checks to accommodate development.

A locked managed FRAME closes its HTTP and HTTPS listeners, so a connection failure does **not** prove it is locked (the daemon may also be stopped). The unavailable panel keeps the error visible and directs you to run `comb cell list` in a terminal to unlock, then choose **Retry**. If the page itself cannot load, unlock first and reload the daemon URL. **Refresh** reloads status and lists; closing/reloading the browser does not lock the daemon. Repeated initial connections while busy are ignored. Use a trusted local machine; non-browser programs can forge provenance headers. The default local endpoint does not add OS-user authentication or TLS. Optional remote HTTPS is a distinct authenticated owner-console boundary, not protection against malicious same-origin scripts or a multi-user account system.

## Available workflows

- Load local identity, FRAME state, and daemon-reported capabilities.
- List, search, sort, and create CELL repositories in a compact repository dashboard. New repository drafts clear and close only after a successful response; failures keep the draft.
- Open a dedicated repository page at `/cells/:id` (Code), `/cells/:id/issues`, `/cells/:id/history`, `/cells/:id/branches`, or `/cells/:id/settings`. React Router links support deep-link reload and browser Back/Forward; the daemon must serve `index.html` for these non-API paths. Repository identity URLs remain stable through rename.
- History shows real Git commit subjects, authors, timestamps, merge indicators, and immutable source snapshot links. Pages contain up to 30 commits; pagination pins the resolved commit so a concurrent push does not shift subsequent pages. Branches lists accepted branch refs with search, code, and history links; branch creation/deletion still uses your Git client.
- The Code clone menu provides HTTP and configured SSH remotes with copy feedback. Clipboard failures leave a selectable URL and explicit manual-copy guidance. HTTP management-token authentication and SSH key passphrases remain separate from FRAME unlock.
- Code defaults to the committed directory tree plus case-insensitive `README.md` rendered beneath it. Select a branch, navigate folders/breadcrumbs, and open text or Markdown files. Revision/path/file selection lives in query parameters, so copied URLs and history retain navigation. Empty repositories/directories/files, missing paths, binary and oversized blobs, symlinks and submodules have explicit states; symlinks/submodules are not followed.
- Markdown uses `react-markdown`, with raw HTML skipped, an explicit link-protocol allowlist, no embedded images (including remote/data images), and readable, horizontally scrolling fenced code. No repository content is executed.
- Settings grant members using profile JSON and a `read`/`write` role, revoke by identity ID, register a FRAME using profile JSON, export the server-provided encrypted snapshot as JSON, rename, and delete the local repository. Drafts are preserved on failures. Delete requires the exact current name and explicitly leaves peers, independent worktrees, and exported backups untouched; success refreshes and returns to the list.
- Search/filter open and closed issues, expand issue descriptions, and create plain-text issues, with error/loading states. Editing/closing remains unavailable rather than simulated.
- List/register peers using ID, HTTP(S) URL, and public key. Registration is not evidence of connectivity or trust.

The Git remote is `${window.location.origin}/git/${cell.slug}.git`. On the Vite development server, `/git` is proxied to the daemon. In this prototype, use the management token as the Git password; do not embed it in the URL. Git itself manages your local working copy and normal clone/fetch/push operations.

Rename updates the effective name and slug from the server response, immediately updating the displayed Git URL. Existing ID-based Git remotes remain supported by the backend. Pull requests, milestones, issue editing/closing, and broader federation controls remain unavailable rather than simulated. The interface only shows state returned by the backend API.

Repository service contracts: `GET /api/cells/:id/tree?revision=…&path=…`, `GET /api/cells/:id/blob?revision=…&path=…`, `POST /rename {name}`, `POST /delete {confirmation}` (response `{deleted:id}`), `POST /members {profile,role}`, `POST /frames <profile JSON directly>`, `POST /revoke {identity_id}`, and `GET /backup` (snapshot JSON). Cell summaries include `slug`. Reads and writes retain the same browser-access headers and error handling.

History contract: `GET /api/cells/:id/history?revision=…&offset=0` returns `{revision, commits:[{id, parents, author, authored_at, subject}], has_more, next_offset}`. Empty repositories return a null revision and no commits. Offsets are nonnegative integers bounded to 10000; pages contain at most 30 entries and Git output is size-bounded. This uses the same active-FRAME/repository permissions and visible-revision validation as tree/blob reads; private refs and arbitrary revision expressions are not accepted.

## Architecture and tests

- `src/service/contracts.ts`: backend DTOs and service boundary.
- `src/service/HttpAdminService.ts`: relative same-origin HTTP transport, webgui marker header (no Bearer auth), same-origin cookies, no-store requests, encoded CELL paths, status errors, and unauthorized-session notification.
- `src/service/BrowserSessionService.ts` / `src/presenter/BrowserSessionPresenter.ts`: local/remote discovery, ephemeral token login, logout, and expired-session transitions; `src/views/BrowserSessionView.tsx` renders the login/unavailable boundary.
- `src/presenter/AdminPresenter.ts`: local dashboard state, validation, loading/error handling and connection orchestration.
- `src/presenter/RepositoryPresenter.ts`: framework-free repository loading, default revision/README selection, stale-result suppression, settings/issue validation and mutation success signals.
- `src/App.tsx` / `src/main.tsx`: stable route table and BrowserRouter composition; views are split into repository, code, safe Markdown, issues and settings components.
- `src/views/`: thin React renderers with local draft/open state. No HTTP calls in components.
- `tests/`: Node's built-in `node:test` runner through `tsx`; presenter behavior, service request contracts, server-rendered component boundary checks, and mounted React lifecycle/Retry/Refresh checks using Happy DOM.

Automatic-access and repository-page changes used actual RED → GREEN service, presenter, and view runs. Mounted input tests install Happy DOM before importing React DOM, so browser input-event detection works. Repository tests cover exact transport payloads, README/default refs, code states, safe Markdown, settings validation, deep-link/tab navigation, actual exact-confirmation form submission, deletion list navigation/refresh, and stale asynchronous responses. `npm run build` type-checks tests and application before Vite bundles. Native Git authentication is separate from WebGUI sessions: local GUI access needs no token, and remote GUI sign-in exchanges it for a cookie without persistent browser token storage.

From the repository root, `make browser-smoke` builds both components and runs `scripts/webgui_browser_smoke.mjs` using Node's built-in CDP transport and a local Chromium executable (`COMB_CHROMIUM` overrides `chromium`). Set `TMPDIR` to private scratch storage. It creates disposable FRAME/browser state, tests automatic connection/reload, CELL creation/form clearing, cross-origin rejection, restart locking, and Retry after CLI unlock, then removes the fixtures. `make https-browser-smoke` additionally requires OpenSSL and NSS `certutil`; it signs a disposable server certificate, establishes isolated browser CA trust without certificate-error bypasses, and verifies direct/proxied HTTPS sign-in, secure cookies, logout/replay, reload, CSRF rejection, and locked restart. Neither smoke changes system CA trust or issues a public certificate. Chromium runs headless with sandboxing disabled only for these isolated fixtures, never for normal browsing.
