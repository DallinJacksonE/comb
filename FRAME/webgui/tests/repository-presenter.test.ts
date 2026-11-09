import { test } from 'node:test';
import assert from 'node:assert/strict';
import { RepositoryPresenter } from '../src/presenter/RepositoryPresenter.ts';
const cell = { id:'c', name:'Garden', slug:'garden', owner:'me', version:'1', refs:{'refs/heads/dev':'abc'}, members:{} };
const tree = {revision:'abc',path:'',entries:[{name:'ReadMe.MD',path:'ReadMe.MD',kind:'blob',size:5}]};
const blob = {revision:'abc',path:'ReadMe.MD',size:5,content:'# Hi',binary:false,truncated:false};
test('code page selects visible fallback branch and reads case insensitive README under tree', async () => {
 const calls: unknown[] = []; const p = new RepositoryPresenter({cell:async()=>cell,tree:async(...args:unknown[])=>{calls.push(args);return tree;},blob:async(...args:unknown[])=>{calls.push(args);return blob;}} as any);
 await p.load('c','code'); assert.equal(p.state.cell,cell); assert.equal(p.state.readme,blob); assert.equal(p.state.tree,tree);
 assert.deepEqual(calls,[['c','refs/heads/dev',''],['c','abc','ReadMe.MD']]);
});
test('settings validate exact confirmation, use server rename, refresh after delete and export snapshot', async () => {
 const calls: unknown[]=[];
 const renamed={...cell,name:'New name',slug:'new-name'};
 const p=new RepositoryPresenter({cell:async()=>cell,renameCell:async(id:string,name:string)=>{calls.push([id,name]);return renamed;},deleteCell:async(id:string,confirmation:string)=>{calls.push([id,confirmation]);return {deleted:id};},backup:async()=>({encrypted:true}),cells:async()=>{calls.push('refresh');return [];}} as any);
 await p.load('c','settings');
 assert.equal(await p.rename(' '),false); assert.equal(await p.rename(' New name '),true); assert.equal(p.state.cell,renamed);
 assert.equal(await p.delete('new name'),false); assert.equal(await p.delete('New name'),true);
 assert.deepEqual(calls,[['c','New name'],['c','New name'],'refresh']);
 assert.deepEqual(await p.exportBackup(),{encrypted:true});
});
test('settings parse profile JSON, grant/revoke and register FRAME without wrapping profile', async()=>{
 const calls: unknown[]=[]; const profile={identity:{id:'p'}};
 const p=new RepositoryPresenter({cell:async()=>cell,grantMember:async(...args:unknown[])=>{calls.push(args);return cell;},registerFrame:async(...args:unknown[])=>{calls.push(args);return cell;},revokeMember:async(...args:unknown[])=>{calls.push(args);return cell;}} as any);
 await p.load('c','settings'); assert.equal(await p.grant('{bad','write'),false);
 assert.equal(await p.grant(JSON.stringify(profile),'write'),true); assert.equal(await p.registerFrame(JSON.stringify(profile)),true); assert.equal(await p.revoke(' p '),true);
 assert.deepEqual(calls,[['c',profile,'write'],['c',profile],['c','p']]);
});
test('issues validate title and append response; failures and empty code states stay explicit',async()=>{
 const issue={id:'i',title:'Bug',body:'Body',closed:false};
 const p=new RepositoryPresenter({cell:async()=>cell,issues:async()=>[],createIssue:async()=>issue,tree:async()=>({revision:null,path:'',entries:[]}),blob:async()=>{throw new Error('Missing path');}} as any);
 await p.load('c','issues'); assert.equal(await p.createIssue(' ','Body'),false); assert.equal(await p.createIssue('Bug','Body'),true); assert.deepEqual(p.state.issues,[issue]);
 await p.load('c','code'); assert.equal(p.state.tree?.revision,null); assert.equal(p.state.readme,null);
 await p.load('c','code','dev','missing',true); assert.match(p.state.error,/Missing path/); assert.equal(p.state.busy,false);
});
test('missing paths retain repository metadata for branch/root recovery',async()=>{
 const p=new RepositoryPresenter({cell:async()=>cell,tree:async()=>{throw new Error('Path not found');}} as any);
 await p.load('c','code','refs/heads/dev','missing');assert.equal(p.state.cell,cell);assert.match(p.state.error,/Path not found/);
});
test('late repository requests cannot replace a newly navigated page',async()=>{
 let resolve!: (value:typeof cell)=>void;const pending=new Promise<typeof cell>(r=>resolve=r);
 const p=new RepositoryPresenter({cell:async(id:string)=>id==='old'?pending:{...cell,id},issues:async()=>[]} as any);
 const old=p.load('old','settings');await p.load('new','issues');resolve(cell);await old;assert.equal(p.state.cell?.id,'new');
});
