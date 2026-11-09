/** Route composition for the dashboard and stable, CELL-ID-based repository pages. */
import { Route, Routes } from 'react-router-dom';
import type { AdminPresenter } from './presenter/AdminPresenter';
import type { RepositoryPresenter } from './presenter/RepositoryPresenter';
import { AdminView } from './views/AdminView';
import { RepositoryView } from './views/RepositoryView';
/** Mount inside BrowserRouter and the session gate; origin is used for Git remotes. */
export function App({admin,repository,origin}: {admin:AdminPresenter;repository:RepositoryPresenter;origin:string}) {
  return <Routes>
    <Route path="/" element={<AdminView presenter={admin} origin={origin}/>}/>
    <Route path="/cells/:id" element={<RepositoryView presenter={repository} origin={origin} tab="code"/>}/>
    <Route path="/cells/:id/issues" element={<RepositoryView presenter={repository} origin={origin} tab="issues"/>}/>
    <Route path="/cells/:id/history" element={<RepositoryView presenter={repository} origin={origin} tab="history"/>}/>
    <Route path="/cells/:id/branches" element={<RepositoryView presenter={repository} origin={origin} tab="branches"/>}/>
    <Route path="/cells/:id/settings" element={<RepositoryView presenter={repository} origin={origin} tab="settings"/>}/>
    <Route path="*" element={<p>Page not found. <a href="/">All CELLs</a></p>}/>
  </Routes>;
}
