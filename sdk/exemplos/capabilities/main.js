cat.pipeline.registerStep({id:'aurora.capabilities.probe',title:{'pt-BR':'Aurora — Serviços HTTP',en:'Aurora — HTTP services'},inputs:['http','endpoint'],outputs:['analysis','endpoint']},async ctx=>{
  const targets=[...new Set(ctx.inputs.map(item=>item.data.url).filter(Boolean))].slice(0,50);
  if(ctx.signal.aborted)return;
  const result=await cat.connectors.run({connector:ctx.config.connector,capability:'http.probe',tool:'httpx',id:'probe',targets,parameters:ctx.config.parameters});
  ctx.emit('analysis',result);
  for(const item of result.results||[])if(item.kind==='http_service')ctx.emit('endpoint',item);
  await ctx.checkpoint({completed:true,count:result.results.length});
  ctx.progress(1);
});
