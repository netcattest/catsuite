const T=(p,e)=>({'pt-BR':p,en:e});
const messages=ctx=>ctx.inputs.filter(a=>a.kind==='http');
const body=m=>m.body && m.body.available ? cat.bytes.toText(m.body.bytes || []) : '';
const forward=ctx=>{ for(const a of messages(ctx))ctx.emit('http',a.data); };

cat.pipeline.registerStep({id:'identity.secrets',title:T('Procurar segredos','Scan for secrets'),inputs:['http','jwt'],outputs:['http','jwt','secret']},ctx=>{
 for(const a of ctx.inputs)ctx.emit(a.kind,a.data);
 for(const a of messages(ctx)) {
  const m=a.data;const raw=JSON.stringify([m.headers,m.request && m.request.headers])+body(m);
  const patterns=[['api-key',/(?:api[_-]?key|x-api-key)["'\s:=]+([A-Za-z0-9_-]{12,80})/gi],['token',/(?:access[_-]?token|secret)["'\s:=]+([A-Za-z0-9_.-]{12,160})/gi]];
  for(const [type,pattern] of patterns)for(const match of raw.matchAll(pattern)) {
   const value=match[1];ctx.emit('secret',{url:m.url,type,length:value.length,masked:value.slice(0,3)+'…'+value.slice(-3),
    confidence:'hypothesis',notice:T('Candidato; confirme o contexto antes de relatar.','Candidate; verify context before reporting.')});
  }
 }
});
