// Install a DOM before React DOM is imported so its input-event feature detection
// matches a browser. Individual tests still create and clean up their own Window.
import { Window } from 'happy-dom';
const bootstrap = new Window({url:'http://localhost/'});
Object.assign(globalThis,{window:bootstrap,document:bootstrap.document});
