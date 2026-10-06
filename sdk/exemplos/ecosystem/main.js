cat.ui.tab.register({id:'ecosystem',title:{'pt-BR':'Proveniência do ecossistema',en:'Ecosystem provenance'},components:[{type:'text',text:{'pt-BR':'Execute um fluxo aprovado para visualizar a origem dos resultados.',en:'Run an approved workflow to inspect result origins.'}}]});
cat.pipeline.registerStep({id:'aurora.ecosystem.collect',title:{'pt-BR':'Aurora — Proveniência do ecossistema',en:'Aurora — Ecosystem provenance'},inputs:['analysis','record','endpoint','jwt','secret','finding'],outputs:['record']},async context=>{
  const records=context.inputs.map(item=>({id:item.id,kind:item.kind,sha256:item.sha256,revision:item.revisionId,module:item.module,protection:item.protection}));

  for(let offset=0;offset<records.length;offset+=64)context.emit('record',{records:records.slice(offset,offset+64),count:records.length,page:offset/64,run:context.runId});
  await cat.storage.set('ecosystem.last',{run:context.runId,records:records.slice(0,100),count:records.length});
  await context.checkpoint({completed:true,count:records.length});

  cat.ui.update('ecosystem',[{type:'text',text:{'pt-BR':'Itens: '+records.length+' · Prévia: até 200 itens.','en':'Items: '+records.length+' · Preview: up to 200 items.'}},{type:'table',columns:[{'pt-BR':'Tipo',en:'Kind'},{'pt-BR':'Módulo',en:'Module'},{'pt-BR':'Proteção',en:'Protection'}],rows:records.slice(0,200).map(row=>[row.kind,row.module.id,row.protection])},{type:'progress',value:1}]);
  context.progress(1);

});
