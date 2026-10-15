# CELL GUARD local web GUI

React + TypeScript + Vite management UI for the local FRAME daemon. This is a prototype console, **not a production-security claim**. It uses your existing local identity; it does not create central accounts.

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

Enter the daemon's local management token in the password field. All API requests use `Authorization: Bearer <token>`. The token is kept only in memory: no localStorage/sessionStorage/cookie persistence, no query-string credentials. Disconnect or reload to clear it. Use a trusted local machine; this UI does not add TLS, a hardened authentication protocol, or protection against malicious same-origin scripts.

## Available workflows

- Load local identity, FRAME state, and daemon-reported capabilities.
- List/create CELL repositories. New repository drafts clear and close only after a successful response; failures keep the draft.
- Expand repository details inline to inspect owner, version, refs, and members.
- View and create plain-text issues, with error/loading states.
- List/register peers using ID, HTTP(S) URL, and public key. Registration is not evidence of connectivity or trust.

The Git remote is `${window.location.origin}/git/${cell.id}.git`. On the Vite development server, `/git` is proxied to the daemon. In this prototype, use the management token as the Git password; do not embed it in the URL. Git itself manages your local working copy and normal clone/fetch/push operations.

Code browsing, pull requests, milestones, issue editing/closing, member changes, and federation controls are explicitly unavailable rather than simulated. The interface only shows state returned by the fixed backend API.

## Architecture and tests

- `src/service/contracts.ts`: backend DTOs and service boundary.
- `src/service/HttpAdminService.ts`: relative HTTP transport, Bearer auth, encoded CELL paths, and status errors.
- `src/presenter/AdminPresenter.ts`: framework-free state, validation, loading/error handling, intent orchestration, and success signals.
- `src/views/`: thin React renderers with local draft/open state. No HTTP calls in components.
- `tests/`: Node's built-in `node:test` runner through `tsx`; presenter behavior, service request contracts, and server-rendered component boundary checks.

Implementation used RED → GREEN presenter slices (connection, connection failure, repository creation, inline issues, peer registration), with actual failing runs before each behavior. `npm run build` type-checks tests and application before Vite bundles.
