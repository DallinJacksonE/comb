/** Browser entry point: compose session discovery, same-origin services, and routing. */
import { useState } from 'react';
import { createRoot } from 'react-dom/client';
import { BrowserRouter } from 'react-router-dom';
import { HttpAdminService } from './service/HttpAdminService';
import { HttpBrowserSessionService } from './service/BrowserSessionService';
import { BrowserSessionPresenter } from './presenter/BrowserSessionPresenter';
import { BrowserSessionView } from './views/BrowserSessionView';
import { AdminPresenter } from './presenter/AdminPresenter';
import { RepositoryPresenter } from './presenter/RepositoryPresenter';
import { App } from './App';
import './styles.css';

const session = new BrowserSessionPresenter(new HttpBrowserSessionService());
const service = new HttpAdminService(undefined, () => { void session.sessionExpired(); });

/** Allocate fresh private state whenever the access gate remounts the workspace. */
function PrivateApp() {
  // Gate unmounts discard all private presenter state and outstanding response targets.
  const [admin] = useState(() => new AdminPresenter(service));
  const [repository] = useState(() => new RepositoryPresenter(service));
  return <App admin={admin} repository={repository} origin={window.location.origin}/>;
}

createRoot(document.getElementById('root')!).render(
  <BrowserRouter><BrowserSessionView presenter={session}><PrivateApp/></BrowserSessionView></BrowserRouter>,
);
