const T=(p,e)=>({'pt-BR':p,en:e});
const messages=ctx=>ctx.inputs.filter(a=>a.kind==='http');
const body=m=>m.body && m.body.available ? cat.bytes.toText(m.body.bytes || []) : '';
const forward=ctx=>{ for(const a of messages(ctx))ctx.emit('http',a.data); };

cat.pipeline.registerStep({id:'identity.authorization',title:T('Analisar objetos','Analyze objects'),inputs:['http','jwt','secret'],outputs:['http','jwt','secret','analysis','finding']},async ctx=>{
 for(const a of ctx.inputs)ctx.emit(a.kind,a.data);
 for(const a of messages(ctx)) {
  const m=a.data;const match=/\/(?:users?|usuarios?|pedidos?|orders?)\/(\d+)(?:[/?#]|$)/i.exec(m.url||'');
  if(!match)continue;
  const analysis={url:m.url,objectId:match[1],confidence:'hypothesis',tested:false,
   notice:T('Objeto na rota; não demonstra falha de autorização.','Object in route; does not demonstrate an authorization flaw.')};ctx.emit('analysis',analysis);
  const finding=await cat.findings.add({fingerprint:'object-route:'+m.url,title:T('Objeto controlável na rota','Potentially controllable object in route'),
   description:T('A rota contém um identificador numérico. Compare acesso com duas identidades autorizadas para validar a hipótese.','The route contains a numeric identifier. Compare access using two authorized identities to validate the hypothesis.'),
   severity:'info',confidence:'hypothesis',url:m.url,evidence:analysis});ctx.emit('finding',{url:m.url,fingerprint:finding,confidence:'hypothesis'});
 }
});
