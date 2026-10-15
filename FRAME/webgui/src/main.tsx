import { createRoot } from 'react-dom/client';
import { HttpAdminService } from './service/HttpAdminService';
import { AdminPresenter } from './presenter/AdminPresenter';
import { AdminView } from './views/AdminView';
import './styles.css';
const presenter = new AdminPresenter(new HttpAdminService());
createRoot(document.getElementById('root')!).render(<AdminView presenter={presenter} origin={window.location.origin} />);
