import './dom.ts';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createElement } from 'react';
import { renderToStaticMarkup as render } from 'react-dom/server';
import { MemoryRouter, useNavigate } from 'react-router-dom';
function HistoryBack() { const navigate=useNavigate();return createElement('button',{onClick:()=>navigate(-1)},'History back'); }
import { SafeMarkdown } from '../src/views/SafeMarkdown.tsx';
import { CodePanel, BlobContent } from '../src/views/CodePanel.tsx';
const wrap=(child: any)=>render(createElement(MemoryRouter,{},child));
test('markdown renders headings/fenced code and safe links but never HTML, active URLs or embedded images',()=>{
 const html=render(createElement(SafeMarkdown,{content:'# Hello\n\n```js\nalert("safe text")\n```\n\n[ok](https://example.com) [bad](javascript:alert%281%29) [data](data:text/html,hi) ![remote](https://example.com/p.png)\n\n<script>alert(1)</script><img src=x onerror=alert(1)>'}));
 assert.match(html,/<h1>Hello<\/h1>/); assert.match(html,/<pre><code class="language-js">/); assert.match(html,/href="https:\/\/example.com"/);
 assert.doesNotMatch(html,/<script|<img|href="(?:javascript|data):|onerror=/); assert.match(html,/remote/);
});
test('code panel displays tree plus README and explicit empty/binary/oversize states',()=>{
 const state:any={revision:'main',path:'',blob:null,readme:{content:'# Welcome',binary:false,truncated:false},tree:{revision:'abc',path:'',entries:[{name:'src',path:'src',kind:'tree',size:null},{name:'file.txt',path:'file.txt',kind:'blob',size:2},{name:'link',path:'link',kind:'symlink',size:2}]}};
 const html=wrap(createElement(CodePanel,{state,cell:{refs:{'refs/heads/main':'abc'}} as any}));
 assert.match(html,/Welcome/); assert.match(html,/path=src/); assert.match(html,/file=1/); assert.match(html,/symlink/);
 for (const [patch,text] of [[{binary:true},/Binary file/],[{truncated:true},/too large/],[{content:''},/Empty file/]] as const) assert.match(render(createElement(BlobContent,{blob:{content:null,...patch} as any})),text);
 assert.match(wrap(createElement(CodePanel,{state:{...state,readme:null,tree:{revision:null,entries:[]}},cell:{refs:{}} as any})),/No commits yet/);
});
import { App } from '../src/App.tsx';
import { AdminPresenter } from '../src/presenter/AdminPresenter.ts';
import { RepositoryPresenter } from '../src/presenter/RepositoryPresenter.ts';
import { SettingsPanel } from '../src/views/SettingsPanel.tsx';
import { RepositoryView } from '../src/views/RepositoryView.tsx';
const cell={id:'c',name:'Garden',slug:'garden',owner:'me',version:'v',refs:{},members:{me:'owner'}};
test('repository shows its automatic SSH alias separately from token-authenticated HTTP',()=>{
 const p=new RepositoryPresenter({} as any);
 p.state={...p.state,cell:{...cell,ssh_remote:'comb-fixture:garden.git'} as any};
 const html=wrap(createElement(RepositoryView,{presenter:p,origin:'http://localhost:7331',tab:'settings'}));
 assert.match(html,/SSH remote URL/); assert.match(html,/comb-fixture:garden.git/); assert.match(html,/passphrase/);
});
test('repository settings render real forms and explicit local deletion scope',()=>{
 const p=new RepositoryPresenter({} as any); p.state={...p.state,cell};
 const html=wrap(createElement(SettingsPanel,{presenter:p,cell,busy:false}));
 for(const text of ['Grant member','Register FRAME','Export encrypted backup','Rename repository','Delete local repository','exact','peers','worktrees','exported backups']) assert.ok(html.includes(text),text);
 assert.doesNotMatch(html, />Revoke<\/button>/, 'the owner must not have a revoke action');
});
test('repository route mounts on deep links, supports tabs/back and refreshes list after deletion', async()=>{
 const {act}=await import('react'); const {createRoot}=await import('react-dom/client'); const {Window}=await import('happy-dom');
 const window=new Window({url:'http://localhost/cells/c/settings'}); const previous={window:globalThis.window,document:globalThis.document}; Object.assign(globalThis,{window,document:window.document,IS_REACT_ACT_ENVIRONMENT:true});
 let lists=0; const service={cell:async()=>cell,status:async()=>({identity:{id:'me',name:'Ada',email:'x'},frame:{id:'f',active:true},cells:1,capabilities:[]}),cells:async()=>{lists++;return lists>1?[]:[cell];},peers:async()=>[],deleteCell:async()=>({deleted:'c'}),issues:async()=>[]};
 const admin=new AdminPresenter(service as any);const repository=new RepositoryPresenter(service as any);const container=document.createElement('div');const root=createRoot(container);
 try {
 await act(async()=>{root.render(createElement(MemoryRouter,{initialEntries:['/cells/c/settings']},createElement(App,{admin,repository,origin:'http://localhost'}),createElement(HistoryBack)));});
 assert.match(container.textContent!,/Garden/);assert.ok(container.querySelector('a[href="/cells/c/issues"]'));assert.ok(container.querySelector('a[href="/cells/c"]'));
 // Navigate via an actual tab link, then Back, exercising the router instead of a tab-state toggle.
 await act(async()=>{(container.querySelector('a[href="/cells/c/issues"]') as HTMLAnchorElement).click();});assert.match(container.textContent!,/New issue/);
 await act(async()=>{Array.from(container.querySelectorAll('button')).find(b=>b.textContent==='History back')!.click();});assert.match(container.textContent!,/Delete local repository/);
 const input=container.querySelector('#delete-confirmation') as HTMLInputElement;
 await act(async()=>{const setter=Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype,'value')!.set!;setter.call(input,'Garden');input.dispatchEvent(new window.Event('input',{bubbles:true}) as any);input.dispatchEvent(new window.Event('change',{bubbles:true}) as any);});
 const deleteButton=Array.from(container.querySelectorAll('button')).find(b=>b.textContent==='Delete local repository')!;
 assert.equal(deleteButton.disabled,false);
 await act(async()=>{deleteButton.closest('form')!.dispatchEvent(new window.Event('submit',{bubbles:true,cancelable:true}) as any);});
 assert.match(container.textContent!,/Your CELLs/); assert.ok(lists>=2);
 }finally {await act(async()=>root.unmount());Object.assign(globalThis,previous);delete (globalThis as any).IS_REACT_ACT_ENVIRONMENT;await window.happyDOM.close();}
});