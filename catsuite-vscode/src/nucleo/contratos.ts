export type Idioma = 'pt-BR' | 'en';
export type Objeto = Record<string, any>;
export type Problema = { codigo: string; gravidade: 'erro' | 'aviso'; caminho: string; argumentos?: Record<string, string | number>; linha?: number; coluna?: number };
export type Projeto = { pasta: string; manifesto: Objeto; arquivos: Record<string, Buffer>; codigo: string; problemas: Problema[] };
export type ResultadoPrevia = { request: Objeto; response: Objeto; eventos: Objeto[]; abas: Objeto[]; menus: Objeto[]; achados: Objeto[]; artefatos: Objeto[]; registros: unknown[]; mensagem: Objeto; comandos: string[]; erros: string[]; duracao: number; memoria: number };
export class Falha extends Error {
  constructor(readonly codigo: string, readonly argumentos: Record<string, string | number> = {}) { super(codigo); }
}
export const limites = Object.freeze({ pacote: 10 * 1024 * 1024, expandido: 40 * 1024 * 1024, arquivo: 4 * 1024 * 1024, manifesto: 64 * 1024, codigo: 128 * 1024, arquivos: 500, fluxo: 256 * 1024, memoria: 32 * 1024 * 1024, previa: 1500 });
export const permissoes = ['traffic.read', 'traffic.modify', 'http.send', 'external.call', 'ui.menu', 'ui.tab', 'storage', 'findings', 'repeater', 'commands', 'pipeline.step', 'parsers', 'connector.run'] as const;
export const tiposArtefato = ['http', 'endpoint', 'jwt', 'secret', 'analysis', 'finding', 'record', 'javascript', 'openapi'];
export const tiposBloco = ['capture', 'filter', 'condition', 'join', 'parser', 'request', 'crawler', 'storage', 'report', 'connector', 'extension'];
export const api: Record<string, { permissao?: string; assinatura: string; pt: string; en: string }> = {
  'events.on': { permissao: 'traffic.read', assinatura: 'cat.events.on(evento, handler)', pt: 'Observa tráfego efetivamente encaminhado.', en: 'Observes forwarded traffic.' },
  'proxy.onRequest': { permissao: 'traffic.modify', assinatura: 'cat.proxy.onRequest(handler)', pt: 'Altera requests em um handler síncrono de até 100 ms.', en: 'Modifies requests in a synchronous handler limited to 100 ms.' },
  'proxy.onResponse': { permissao: 'traffic.modify', assinatura: 'cat.proxy.onResponse(handler)', pt: 'Altera responses em um handler síncrono de até 100 ms.', en: 'Modifies responses in a synchronous handler limited to 100 ms.' },
  'http.send': { permissao: 'http.send', assinatura: 'await cat.http.send(request)', pt: 'Envia uma request somente aos destinos aprovados.', en: 'Sends a request only to approved destinations.' },
  'http.cancel': { permissao: 'http.send', assinatura: 'cat.http.cancel(id)', pt: 'Cancela um envio da extensão.', en: 'Cancels an extension request.' },
  'http.parseUrl': { assinatura: 'cat.http.parseUrl(url)', pt: 'Interpreta uma URL sem Node.js ou DOM.', en: 'Parses a URL without Node.js or DOM.' },
  'external.call': { permissao: 'external.call', assinatura: 'await cat.external.call(options)', pt: 'Usa externalHosts e referências de credencial do host.', en: 'Uses externalHosts and host credential references.' },
  'laboratory.capture': { permissao: 'traffic.read', assinatura: 'await cat.laboratory.capture(request)', pt: 'Executa uma captura com fixtures do laboratório.', en: 'Captures a request using laboratory fixtures.' },
  'ui.menu.register': { permissao: 'ui.menu', assinatura: 'cat.ui.menu.register(options)', pt: 'Adiciona uma ação contextual de request/response.', en: 'Adds a request/response context action.' },
  'ui.tab.register': { permissao: 'ui.tab', assinatura: 'cat.ui.tab.register(options)', pt: 'Cria uma aba de componentes nativos, sem HTML.', en: 'Creates a native component tab without HTML.' },
  'ui.update': { permissao: 'ui.tab', assinatura: 'cat.ui.update(id, components)', pt: 'Atualiza componentes de uma aba registrada.', en: 'Updates components of a registered tab.' },
  'storage.get': { permissao: 'storage', assinatura: 'await cat.storage.get(key)', pt: 'Lê dados privados desta extensão.', en: 'Reads this extension’s private data.' },
  'storage.set': { permissao: 'storage', assinatura: 'await cat.storage.set(key, value)', pt: 'Salva JSON, até 128 KiB por valor.', en: 'Stores JSON, up to 128 KiB per value.' },
  'storage.delete': { permissao: 'storage', assinatura: 'await cat.storage.delete(key)', pt: 'Remove um valor salvo.', en: 'Removes a stored value.' },
  'findings.add': { permissao: 'findings', assinatura: 'await cat.findings.add(finding)', pt: 'Registra um achado com evidência e confiança explícita.', en: 'Records a finding with evidence and explicit confidence.' },
  'commands.register': { permissao: 'commands', assinatura: 'cat.commands.register(id, title, handler)', pt: 'Registra um comando próprio e bilíngue.', en: 'Registers a custom bilingual command.' },
  'commands.execute': { permissao: 'commands', assinatura: 'await cat.commands.execute(id, args)', pt: 'Executa um comando da própria extensão.', en: 'Executes a command from the same extension.' },
  'tools.repeater.open': { permissao: 'repeater', assinatura: 'cat.tools.repeater.open(request)', pt: 'Abre uma mensagem no Repetir.', en: 'Opens a message in Repeater.' },
  'pipeline.registerStep': { permissao: 'pipeline.step', assinatura: 'cat.pipeline.registerStep(options, handler)', pt: 'Registra entradas e saídas tipadas para fluxos.', en: 'Registers typed workflow inputs and outputs.' },
  'parsers.register': { permissao: 'parsers', assinatura: 'cat.parsers.register(options, handler)', pt: 'Registra um parser com formatos reconhecidos.', en: 'Registers a parser with recognized formats.' },
  'connectors.capabilities': { permissao: 'connector.run', assinatura: 'await cat.connectors.capabilities(connectorId)', pt: 'Consulta o catálogo assinado do conector.', en: 'Reads the connector’s signed capability catalog.' },
  'connectors.run': { permissao: 'connector.run', assinatura: 'await cat.connectors.run(options)', pt: 'Solicita uma capacidade tipada, nunca shell ou argumentos livres.', en: 'Requests a typed capability, never shell or arbitrary arguments.' },
  'connectors.cancel': { permissao: 'connector.run', assinatura: 'cat.connectors.cancel(id)', pt: 'Cancela a tarefa autorizada.', en: 'Cancels an authorized task.' },
  'settings.get': { assinatura: 'cat.settings.get(key)', pt: 'Lê a configuração definida pelo usuário.', en: 'Reads user-defined configuration.' },
  'resources.get': { assinatura: 'await cat.resources.get(path, mode)', pt: 'Lê um recurso declarado no pacote.', en: 'Reads a declared package resource.' },
  'i18n.text': { assinatura: 'cat.i18n.text(text)', pt: 'Seleciona pt-BR ou inglês.', en: 'Selects Brazilian Portuguese or English.' },
  'bytes.fromText': { assinatura: 'cat.bytes.fromText(text)', pt: 'Converte texto UTF-8 em bytes.', en: 'Converts UTF-8 text to bytes.' },
  'bytes.toText': { assinatura: 'cat.bytes.toText(bytes)', pt: 'Converte bytes UTF-8 em texto.', en: 'Converts UTF-8 bytes to text.' },
  'log': { assinatura: 'cat.log(message, level)', pt: 'Registra execução sem inserir segredos.', en: 'Logs execution without including secrets.' }
};
