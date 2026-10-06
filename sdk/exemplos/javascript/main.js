const T=(p,e)=>({'pt-BR':p,en:e});
const messages=ctx=>ctx.inputs.filter(a=>a.kind==='http');
const body=m=>m.body && m.body.available ? cat.bytes.toText(m.body.bytes || []) : '';
const forward=ctx=>{ for(const a of messages(ctx))ctx.emit('http',a.data); };

cat.pipeline.registerStep({id:'api.javascript',title:T('Analisar JavaScript','Analyze JavaScript'),inputs:['http'],outputs:['http','javascript']},ctx=>{
 forward(ctx);
 for(const a of messages(ctx)) {
  const m=a.data;const content=body(m);if(!content)continue;
  ctx.emit('javascript',{url:m.url,content,complete:!!m.body.complete,notice:T('Análise estática local; o código não é executado.','Local static analysis; code is not executed.')});
 }
});
cat.parsers.register({id:'api.json',title:T('Ler JSON','Parse JSON'),inputs:['http'],outputs:['record'],mimeTypes:['application/json']},ctx=>{
 for(const a of messages(ctx)){if(!a.data.body.complete)throw new Error('E_BODY');ctx.emit('record',JSON.parse(body(a.data)));}
});
