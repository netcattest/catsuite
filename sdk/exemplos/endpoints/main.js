const T=(p,e)=>({'pt-BR':p,en:e});
const messages=ctx=>ctx.inputs.filter(a=>a.kind==='http');
const body=m=>m.body && m.body.available ? cat.bytes.toText(m.body.bytes || []) : '';
const forward=ctx=>{ for(const a of messages(ctx))ctx.emit('http',a.data); };

cat.pipeline.registerStep({id:'api.endpoints',title:T('Extrair endpoints','Extract endpoints'),inputs:['http','javascript'],outputs:['endpoint']},ctx=>{
 const seen=new Set();
 for(const a of ctx.inputs) {
  const m=a.data;const base=(m.url||'').split('/').slice(0,3).join('/');const code=m.content||body(m);
  const candidates=[m.url,...Array.from(code.matchAll(/["'`](\/api\/[^"'`\s<>]+)["'`]/g),v=>base+v[1])];
  for(const url of candidates){if(!url||seen.has(url)||seen.size>=100)continue;seen.add(url);ctx.emit('endpoint',{url,sourceUrl:m.url,method:'GET',confidence:'observed',discoveredOnly:true});}
 }
});
