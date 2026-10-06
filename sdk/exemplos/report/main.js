const T=(p,e)=>({'pt-BR':p,en:e});
const messages=ctx=>ctx.inputs.filter(a=>a.kind==='http');
const body=m=>m.body && m.body.available ? cat.bytes.toText(m.body.bytes || []) : '';
const forward=ctx=>{ for(const a of messages(ctx))ctx.emit('http',a.data); };

cat.pipeline.registerStep({id:'identity.report',title:T('Consolidar relatório','Build report'),inputs:['http','jwt','secret','analysis','finding','endpoint','record'],outputs:['record']},async ctx=>{
 const counts={};for(const a of ctx.inputs)counts[a.kind]=(counts[a.kind]||0)+1;
 const report={runId:ctx.runId,counts,total:ctx.inputs.length,notice:T('Resultados observados e hipóteses separados.','Observed results and hypotheses kept distinct.')};
 await cat.storage.set('last-report',report);ctx.emit('record',report);
 cat.ui.update('report.panel',[{type:'chart',label:T('Resultados por tipo','Results by type'),values:Object.entries(counts).map(([label,value])=>({label,value}))},
  {type:'timeline',items:[{title:T('Relatório salvo','Report saved'),detail:ctx.runId}]}]);
});
cat.ui.tab.register({id:'report.panel',title:T('Relatórios','Reports'),components:[{type:'text',text:T('Execute um fluxo para ver o resumo.','Run a workflow to view its summary.')} ]});
