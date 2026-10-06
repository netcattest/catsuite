const T=(p,e)=>({'pt-BR':p,en:e});
const messages=ctx=>ctx.inputs.filter(a=>a.kind==='http');
const body=m=>m.body && m.body.available ? cat.bytes.toText(m.body.bytes || []) : '';
const forward=ctx=>{ for(const a of messages(ctx))ctx.emit('http',a.data); };

function decode64(value) {
 const alphabet='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
 let bits=0,acc=0;const bytes=[];
 for(const char of value.replace(/-/g,'+').replace(/_/g,'/')) {
  if(char==='=')break;const n=alphabet.indexOf(char);if(n<0)throw new Error('E_JWT');
  acc=(acc<<6)|n;bits+=6;if(bits>=8){bits-=8;bytes.push((acc>>bits)&255);}
 }
 if(bytes.length>16384)throw new Error('E_SIZE');return JSON.parse(cat.bytes.toText(bytes));
}
cat.pipeline.registerStep({id:'identity.jwt',title:T('Analisar JWT','Analyze JWT'),inputs:['http'],outputs:['http','jwt']},ctx=>{
 forward(ctx);
 for(const artifact of messages(ctx)) {
  const m=artifact.data;const headers=[...(m.headers||[]),...(m.request && m.request.headers||[])];
  for(const h of headers) {
   const found=/Bearer\s+([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*)/i.exec(h.value||'');if(!found)continue;
   try { const parts=found[1].split('.');const header=decode64(parts[0]);const claims=decode64(parts[1]);
    ctx.emit('jwt',{url:m.url,algorithm:header.alg,claims,expires:claims.exp||null,signatureVerified:false,
     notice:T('Assinatura não verificada; leitura local das claims.','Signature not verified; local claims inspection.')});
   } catch(e) { ctx.emit('jwt',{url:m.url,error:'E_JWT',signatureVerified:false}); }
  }
 }
});
