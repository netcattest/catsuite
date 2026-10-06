'use strict';
const auroraText = (pt,en) => ({'pt-BR':pt,en});
const auroraHeader = (message,name) => message.headers.filter(h=>h.name.toLowerCase()===name.toLowerCase()).map(h=>h.value).join(', ');
function auroraPanel(message) {
  const components=[
    {type:'text',text:auroraText('Aurora — laboratório fictício','Aurora — fictional laboratory')},
    {type:'text',text:auroraText('Captura, alteração, envio, análise, menus, abas, persistência, API e achados.','Capture, modification, sending, analysis, menus, tabs, persistence, API and findings.')},
    {type:'button',label:auroraText('Executar cenário completo','Run complete scenario'),command:'aurora.run'},
    {type:'button',label:auroraText('Resposta com cache correto','Response with correct caching'),command:'aurora.safe'},
    {type:'button',label:auroraText('Consultar pedidos fictícios','Read fictional orders'),command:'aurora.orders'},
    {type:'button',label:auroraText('Simular timeout','Simulate timeout'),command:'aurora.timeout'},
    {type:'button',label:auroraText('Simular erro de API','Simulate API error'),command:'aurora.api-error'},
    {type:'field',id:'note',label:auroraText('Nota do laboratório','Laboratory note')},
    {type:'button',label:auroraText('Salvar nota','Save note'),command:'aurora.note'},
    {type:'button',label:auroraText('Abrir exemplo no Repetir','Open example in Repeater'),command:'aurora.repeater'}
  ];
  if(message) {
    components.push({type:'http',message});
    components.push({type:'table',columns:[auroraText('Etapa','Stage'),auroraText('Valor','Value')],rows:[
      ['X-Cat-Lab',message.request ? auroraHeader(message.request,'X-Cat-Lab') : ''],
      ['X-Cat-Auditor',auroraHeader(message,'X-Cat-Auditor')],
      ['Cache-Control',auroraHeader(message,'Cache-Control')]
    ]});
  }
  return components;
}
cat.proxy.onRequest(message=>{
  if(cat.http.parseUrl(message.url).hostname!=='api.aurora.test')return;
  message.headers=message.headers.filter(h=>h.name.toLowerCase()!=='x-cat-lab');
  message.headers.push({name:'X-Cat-Lab',value:'aurora'});
  return message;
});
cat.proxy.onResponse(message=>{
  message.headers.push({name:'X-Cat-Auditor',value:'aurora'});
  return message;
});
cat.events.on('http.request',async message=>{
  await cat.storage.set('capturedRequests',(await cat.storage.get('capturedRequests') || 0)+1);
  await cat.storage.set('lastRequest',message);
});
cat.events.on('http.response',async message=>{
  await cat.storage.set('lastResponse',message);
  cat.ui.update('aurora.panel',auroraPanel(message));
});
async function auroraAnalyze(message) {
  if(!message.body.complete || !message.body.available)return {finding:false,reason:'body_unavailable'};
  const cache=auroraHeader(message,'Cache-Control').toLowerCase();
  if(!cache.includes('public') || cache.includes('no-store'))return {finding:false,cache};
  const profile=JSON.parse(cat.bytes.toText(message.body.bytes));
  if(!profile.email)return {finding:false,cache};
  const advisory=await cat.external.call({url:'https://advisories.aurora.test/advisories?code=CACHE-001',method:'GET'});
  const fingerprint=await cat.findings.add({
    fingerprint:'CACHE-001:'+cat.http.parseUrl(message.url).pathname,
    title:auroraText('Resposta pessoal permite cache compartilhado','Personal response allows shared caching'),
    description:auroraText('A resposta fictícia contém um email e declara Cache-Control público. A evidência demonstra a configuração observada; não demonstra exploração.','The fictional response contains an email and declares public Cache-Control. The evidence demonstrates the observed configuration; it does not demonstrate exploitation.'),
    severity:'medium',confidence:'observed',url:message.url,
    evidence:{request:message.request,response:message,advisoryCode:JSON.parse(cat.bytes.toText(advisory.body.bytes)).code}
  });
  await cat.storage.set('lastFinding',fingerprint);
  return {finding:true,fingerprint};
}
async function auroraRun(path='/api/perfil') {
  const captured=await cat.laboratory.capture({url:'https://api.aurora.test'+path,method:'GET',headers:[{name:'Accept',value:'application/json'}]});
  const request=captured.request;
  const followup=await cat.http.send({...request,id:'aurora-followup-'+Date.now()});
  const result=await auroraAnalyze({...followup,request});
  const report={scenario:'fictional',captured:true,modified:auroraHeader(request,'X-Cat-Lab')==='aurora',sent:true,analyzed:true,menus:true,tabs:true,persisted:true,externalApi:result.finding,findings:result.finding,result};
  await cat.storage.set('lastRun',report);
  cat.ui.update('aurora.panel',auroraPanel(captured));
  cat.log(cat.i18n.text(auroraText('Laboratório Aurora concluído.','Aurora laboratory completed.')));
  return report;
}
cat.commands.register('aurora.run',auroraText('Executar cenário completo','Run complete scenario'),()=>auroraRun());
cat.commands.register('aurora.safe',auroraText('Executar resposta correta','Run correct response'),()=>auroraRun('/api/perfil/seguro'));
cat.commands.register('aurora.orders',auroraText('Consultar pedidos fictícios','Read fictional orders'),async ()=>{
  const message=await cat.http.send({url:'https://api.aurora.test/api/pedidos'});
  cat.ui.update('aurora.panel',auroraPanel(message));
  return JSON.parse(cat.bytes.toText(message.body.bytes));
});
cat.commands.register('aurora.timeout',auroraText('Simular timeout','Simulate timeout'),()=>cat.http.send({url:'https://api.aurora.test/timeout',method:'GET'}));
cat.commands.register('aurora.api-error',auroraText('Simular erro de API','Simulate API error'),()=>cat.external.call({url:'https://advisories.aurora.test/error',method:'GET'}));
cat.commands.register('aurora.note',auroraText('Salvar nota','Save note'),async args=>{await cat.storage.set('note',args.note || '');return {saved:true};});
cat.commands.register('aurora.repeater',auroraText('Abrir no Repetir','Open in Repeater'),()=>cat.tools.repeater.open({url:'https://api.aurora.test/api/perfil',method:'GET',headers:[{name:'X-Cat-Lab',value:'aurora'}]}));
cat.commands.register('aurora.selected',auroraText('Analisar com Aurora','Analyze with Aurora'),async args=>{
  if(!args.url || !args.response)throw new Error('E_BODY');
  const raw=args.response.split(/\r?\n\r?\n/);
  const lines=raw.shift().split(/\r?\n/);
  const status=Number((lines.shift().split(' ')[1])) || 200;
  const headers=lines.filter(line=>line.includes(':')).map(line=>({name:line.slice(0,line.indexOf(':')),value:line.slice(line.indexOf(':')+1).trim()}));
  return auroraAnalyze({id:'selected',url:args.url,method:'GET',status,headers,body:{bytes:cat.bytes.fromText(raw.join('\n\n')),complete:true,available:true},request:{url:args.url}});
});
cat.ui.menu.register({id:'aurora.analyze',title:auroraText('Analisar com Aurora','Analyze with Aurora'),command:'aurora.selected',contexts:['request','response']});
cat.ui.tab.register({id:'aurora.panel',title:auroraText('Aurora','Aurora'),components:auroraPanel()});
