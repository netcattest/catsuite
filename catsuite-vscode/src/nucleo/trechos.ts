import { api } from './contratos';
export function trechoSdk(nome: string): string {
  const titulo = "{ 'pt-BR': '${1:Título}', en: '${2:Title}' }";
  const trechos: Record<string,string> = {
    'events.on': "cat.events.on('${1:http.complete}', async mensagem => {\n  ${0}\n});",
    'proxy.onRequest': 'cat.proxy.onRequest(mensagem => {\n  ${0}\n  return mensagem;\n});',
    'proxy.onResponse': 'cat.proxy.onResponse(mensagem => {\n  ${0}\n  return mensagem;\n});',
    'http.send': "await cat.http.send({ url: '${1:https://api.aurora.test/api/perfil}', method: '${2:GET}', headers: [] });${0}",
    'http.cancel': "cat.http.cancel('${1:request-id}');${0}",
    'http.parseUrl': "cat.http.parseUrl('${1:https://api.aurora.test}');${0}",
    'external.call': "await cat.external.call({ url: '${1:https://api.aurora.test}', method: '${2:GET}' });${0}",
    'laboratory.capture': "await cat.laboratory.capture({ url: '${1:https://api.aurora.test/api/perfil}', method: 'GET' });${0}",
    'ui.tab.register': "cat.ui.tab.register({ id: '${3:painel}', title: " + titulo + ', components: [${0}] });',
    'ui.menu.register': "cat.ui.menu.register({ id: '${3:menu}', title: " + titulo + ", command: '${4:analisar}', contexts: ['request', 'response'] });${0}",
    'ui.update': "cat.ui.update('${1:painel}', [${0}]);",
    'commands.register': "cat.commands.register('${3:executar}', " + titulo + ', async argumentos => {\n  ${0}\n});',
    'commands.execute': "await cat.commands.execute('${1:executar}', {${0}});",
    'pipeline.registerStep': "cat.pipeline.registerStep({ id: '${3:inspecionar}', title: " + titulo + ", inputs: ['http'], outputs: ['analysis'] }, async contexto => {\n  ${0}\n  contexto.progress(1);\n});",
    'parsers.register': "cat.parsers.register({ id: '${3:parser}', title: " + titulo + ", mimeTypes: ['application/json'], inputs: ['http'], outputs: ['analysis'] }, contexto => {\n  ${0}\n});",
    'findings.add': "await cat.findings.add({ title: " + titulo + ", description: { 'pt-BR': '${3:Descrição}', en: '${4:Description}' }, severity: 'info', confidence: 'observed', url: '${5:https://api.aurora.test}' });${0}",
    'storage.get': "await cat.storage.get('${1:chave}');${0}", 'storage.set': "await cat.storage.set('${1:chave}', {${0}});", 'storage.delete': "await cat.storage.delete('${1:chave}');${0}",
    'settings.get': "cat.settings.get('${1:opcao}');${0}", 'resources.get': "await cat.resources.get('${1:recursos/exemplo.json}', '${2:text}');${0}",
    'tools.repeater.open': 'cat.tools.repeater.open(${1:mensagem});${0}',
    'connectors.capabilities': "await cat.connectors.capabilities('${1:connector-id}');${0}",
    'connectors.run': "await cat.connectors.run({ connector: '${1:connector-id}', capability: '${2:http.probe}', targets: ['${3:https://api.aurora.test}'] });${0}",
    'connectors.cancel': "cat.connectors.cancel('${1:task-id}');${0}",
    'i18n.text': 'cat.i18n.text('+titulo+');${0}', 'bytes.fromText': "cat.bytes.fromText('${1:texto}');${0}", 'bytes.toText': 'cat.bytes.toText(${1:bytes});${0}', 'log': 'cat.log('+titulo+", '${3:info}');${0}"
  };
  if (!api[nome]) return '';
  return trechos[nome] ?? api[nome]!.assinatura.replace(/\((.*)\)/, '(${1:$1})') + ';${0}';
}
export function prefixoCat(linha: string): string | undefined { return linha.match(/(?:^|[^a-zA-Z\d_$])(catplug[\w.]*|cat(?:\.[\w]*)*)$/)?.[1]; }
