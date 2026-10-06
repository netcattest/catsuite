const T=(p,e)=>({'pt-BR':p,en:e});
const messages=ctx=>ctx.inputs.filter(a=>a.kind==='http');
const body=m=>m.body && m.body.available ? cat.bytes.toText(m.body.bytes || []) : '';
const forward=ctx=>{ for(const a of messages(ctx))ctx.emit('http',a.data); };

cat.pipeline.registerStep({id:'api.openapi',title:T('Comparar com OpenAPI','Compare with OpenAPI'),inputs:['endpoint'],outputs:['endpoint','analysis']},async ctx=>{
 const spec=ctx.config.openapi||JSON.parse(await cat.resources.get('openapi.json'));
 for(const a of ctx.inputs) {
  const endpoint=a.data;const path=cat.http.parseUrl(endpoint.url).pathname;const documented=Object.keys(spec.paths||{}).some(p=>{
   const parts=p.split('/');const current=path.split('/');return parts.length===current.length && parts.every((part,i)=>/^\{[^}]+\}$/.test(part)||part===current[i]);
  });ctx.emit('endpoint',endpoint);ctx.emit('analysis',{url:endpoint.url,documented,confidence:'observed',
   notice:documented?T('Endpoint documentado.','Documented endpoint.'):T('Endpoint ausente nesta especificação; confirme a versão.','Endpoint absent from this specification; check its version.')});
 }
});
