import { getQuickJS } from 'quickjs-emscripten';
import { Objeto, Falha, limites, ResultadoPrevia } from './contratos';
import { api } from './contratos';
import { ocultarSegredos } from './seguranca';
export async function executarPrevia(entrada: { codigo: string; manifesto: Objeto; fixture: Objeto; idioma: string; arquivos?: Record<string, string>; comando?: string }): Promise<ResultadoPrevia> {
  const inicio = Date.now(); const motor = await getQuickJS(); const ambiente = motor.newRuntime(); ambiente.setMemoryLimit(limites.memoria); ambiente.setMaxStackSize(512 * 1024);
  let prazo = Date.now() + limites.previa; ambiente.setInterruptHandler(() => Date.now() > prazo);
  const contexto = ambiente.newContext();
  const definir = (nome: string, funcao: (...valores: any[]) => any) => { const h = contexto.newFunction(nome, (...args) => contexto.newString(JSON.stringify(funcao(...args.map(a => contexto.dump(a)))))); contexto.setProp(contexto.global, nome, h); h.dispose(); };
  definir('__utf8', (modo: string, valor: unknown) => { if (modo === 'bytes' && typeof valor === 'string' && Buffer.byteLength(valor) <= 128 * 1024) return Array.from(Buffer.from(valor)); if (modo === 'text' && Array.isArray(valor) && valor.length <= 128 * 1024 && valor.every(v => Number.isInteger(v) && v >= 0 && v <= 255)) return Buffer.from(valor).toString('utf8'); throw new Falha('tamanho'); });
  definir('__url', (valor: string) => { const u = new URL(valor); if (!['http:', 'https:'].includes(u.protocol) || u.username || u.password) throw new Falha('destinoInvalido'); return { scheme: u.protocol.slice(0, -1), hostname: u.hostname, port: Number(u.port || (u.protocol === 'https:' ? 443 : 80)), pathname: u.pathname, query: u.search }; });
  const avaliar = (codigo: string): void => { const resultado = contexto.evalCode(codigo); if (resultado.error) { const e = contexto.dump(resultado.error); resultado.error.dispose(); throw new Falha('execucaoFalhou', { detalhe: String(e?.message ?? e) }); } resultado.value.dispose(); };
  const dados = JSON.stringify({ manifesto: entrada.manifesto, fixture: entrada.fixture, idioma: entrada.idioma, arquivos: entrada.arquivos ?? {}, comando: entrada.comando, api: Object.fromEntries(Object.entries(api).filter(([, v]) => v.permissao).map(([k, v]) => [k, v.permissao])) });
  try {
    avaliar(`(() => {
const dados = ${dados};
const respostaInicial = dados.fixture.response || dados.fixture;
const requestInicial = dados.fixture.request || { ...respostaInicial, id: 'fixture-request', stage: 'request', status: undefined, reason: undefined, headers: [], body: { bytes: [], available: true, complete: true, truncated: false, mutable: true } };
const estado = { request: requestInicial, response: respostaInicial, eventos: [], abas: [], menus: [], achados: [], artefatos: [], registros: [], mensagem: respostaInicial, comandos: [], erros: [] };
const handlers = { eventos: [], request: [], response: [], etapas: [], comandos: Object.create(null) };
const armazenamento = Object.create(null);
const copiar = valor => JSON.parse(JSON.stringify(valor));
const traducao = valor => typeof valor === 'string' ? valor : valor?.[dados.idioma] || valor?.['pt-BR'] || valor?.en || '';
const registrar = (tipo, objeto) => { if (estado[tipo].length >= 1000) throw Error('E_QUOTA'); estado[tipo].push(copiar(objeto)); };
const autorizar = permissao => { if (!dados.manifesto.permissions.includes(permissao)) throw Error('E_PERMISSION: ' + permissao); };
const corresponde = url => { const alvo = JSON.parse(__url(url)); return dados.manifesto.targets.some(regra => { const r = JSON.parse(__url(regra.includes('://') ? regra : 'https://' + regra)); return alvo.hostname === r.hostname && alvo.port === r.port && alvo.scheme === r.scheme && alvo.pathname.startsWith(r.pathname); }); };
const envio = async opcoes => { autorizar('http.send'); if (!corresponde(opcoes.url)) throw Error('E_SCOPE'); const resposta = copiar(estado.response); resposta.url = opcoes.url; resposta.source = 'laboratory'; registrar('eventos', { tipo: 'http.send', simulado: true, url: opcoes.url }); return resposta; };
const operacoes = {
apiVersion: 1, sdkVersion: '1.4.0',
events: { on: (nome, handler) => { autorizar('traffic.read'); handlers.eventos.push({ nome, handler }); } },
proxy: { onRequest: handler => { autorizar('traffic.modify'); handlers.request.push(handler); }, onResponse: handler => { autorizar('traffic.modify'); handlers.response.push(handler); } },
http: { send: envio, cancel: id => { autorizar('http.send'); registrar('eventos', { tipo: 'http.cancel', id }); }, parseUrl: url => JSON.parse(__url(url)) },
external: { call: async opcoes => { autorizar('external.call'); const u = JSON.parse(__url(opcoes.url)); if (!dados.manifesto.externalHosts.some(regra => JSON.parse(__url(regra.includes('://') ? regra : 'https://' + regra)).hostname === u.hostname)) throw Error('E_SCOPE'); registrar('eventos', { tipo: 'external.call', simulado: true, url: opcoes.url }); return copiar(estado.response); } },
laboratory: { capture: async opcoes => { autorizar('traffic.read'); const m = copiar(estado.response); m.url = opcoes.url; registrar('eventos', { tipo: 'laboratory.capture', simulado: true }); return m; } },
ui: { menu: { register: opcoes => { autorizar('ui.menu'); registrar('menus', opcoes); } }, tab: { register: opcoes => { autorizar('ui.tab'); registrar('abas', opcoes); } }, update: (id, componentes) => { autorizar('ui.tab'); const aba = estado.abas.find(a => a.id === id); if (!aba) throw Error('E_TAB'); aba.components = copiar(componentes); } },
storage: { get: async chave => { autorizar('storage'); return armazenamento[chave] === undefined ? null : copiar(armazenamento[chave]); }, set: async (chave, valor) => { autorizar('storage'); const s = JSON.stringify(valor); if (s.length > 131072) throw Error('E_QUOTA'); armazenamento[chave] = JSON.parse(s); }, delete: async chave => { autorizar('storage'); delete armazenamento[chave]; } },
settings: { get: chave => dados.manifesto.settings[chave] ?? null },
resources: { get: async (nome, modo) => { if (!Object.hasOwn(dados.arquivos, nome)) throw Error('E_PATH'); const texto = dados.arquivos[nome]; return modo === 'bytes' ? JSON.parse(__utf8('bytes', texto)) : texto; } },
findings: { add: async achado => { autorizar('findings'); const id = 'studio-finding-' + estado.achados.length; registrar('achados', { ...achado, id }); return id; } },
commands: { register: (id, titulo, handler) => { autorizar('commands'); handlers.comandos[id] = handler; estado.comandos.push(id); }, execute: async (id, args = {}) => { autorizar('commands'); if (!handlers.comandos[id]) throw Error('E_COMMAND'); await handlers.comandos[id](args); return id; } },
tools: { repeater: { open: request => { autorizar('repeater'); registrar('eventos', { tipo: 'repeater.open', request }); } } },
pipeline: { registerStep: (opcoes, handler) => { autorizar('pipeline.step'); handlers.etapas.push({ opcoes, handler }); } },
parsers: { register: (opcoes, handler) => { autorizar('parsers'); handlers.etapas.push({ opcoes, handler }); } },
connectors: { capabilities: async id => { autorizar('connector.run'); registrar('eventos', { tipo: 'connector.catalog', simulado: true }); return { id, protocolVersion: 2, capabilities: [] }; }, run: async opcoes => { autorizar('connector.run'); registrar('eventos', { tipo: 'connector.run', simulado: true, capability: opcoes.capability }); return { id: opcoes.id || 'studio', status: 'complete', results: [], receipts: [], batches: [] }; }, cancel: id => { autorizar('connector.run'); registrar('eventos', { tipo: 'connector.cancel', id }); } },
i18n: { locale: dados.idioma, text: traducao },
bytes: { fromText: texto => JSON.parse(__utf8('bytes', texto)), toText: bytes => JSON.parse(__utf8('text', bytes)) },
log: (mensagem, nivel = 'info') => registrar('registros', { mensagem: traducao(mensagem), nivel })
};
function congelar(o) { for (const v of Object.values(o)) if (v && typeof v === 'object') congelar(v); return Object.freeze(o); }
Object.defineProperty(globalThis, 'cat', { value: congelar(operacoes), configurable: false, writable: false });
const transformar = (tipo, indice) => { const m = copiar(estado[tipo]); m.stage = tipo; const resultado = handlers[tipo][indice](m); if (resultado?.then) throw Error('E_SYNC_HANDLER'); estado[tipo] = resultado || m; estado.mensagem = estado[tipo]; };
const executar = async () => {
for (const evento of handlers.eventos) { if (!['http.request', 'http.response', 'http.complete'].includes(evento.nome)) continue; const mensagemEvento = evento.nome === 'http.request' ? estado.request : { ...estado.response, request: copiar(estado.request) }; await evento.handler(copiar(mensagemEvento)); registrar('eventos', { tipo: evento.nome }); }
for (const etapa of handlers.etapas) { const ctx = { inputs: [{ id: 'fixture', kind: 'http', schemaVersion: 1, data: copiar(estado.mensagem), protection: 'PUBLIC', protected: false, sources: [], run: 'studio', node: etapa.opcoes.id, revisionId: 'studio' }], config: {}, runId: 'studio', nodeId: etapa.opcoes.id, revisionId: 'studio', protection: 'PUBLIC', restored: null, signal: Object.freeze({ aborted: false }), emit: (kind, data) => { if (!etapa.opcoes.outputs.includes(kind)) throw Error('E_TYPE'); registrar('artefatos', { kind, data }); }, progress: value => registrar('eventos', { tipo: 'progress', value }), checkpoint: async estado => { if (JSON.stringify(estado).length > 32768) throw Error('E_CHECKPOINT'); registrar('eventos', { tipo: 'checkpoint', estado }); return true; } }; await etapa.handler(ctx); }
const comando = dados.comando || estado.comandos[0]; if (comando && handlers.comandos[comando]) await handlers.comandos[comando]({});
return estado;
};
globalThis.__catPrevia = { transformar, executar, quantidade: tipo => handlers[tipo].length };
})();`);
    avaliar(entrada.codigo);
    for (const tipo of ['request', 'response']) {
      const h = contexto.evalCode(`__catPrevia.quantidade(${JSON.stringify(tipo)})`); const quantidade = contexto.unwrapResult(h).consume(contexto.dump);
      for (let indice = 0; indice < Number(quantidade); indice++) { prazo = Date.now() + 100; avaliar(`__catPrevia.transformar(${JSON.stringify(tipo)}, ${indice})`); }
    }
    prazo = Date.now() + limites.previa;
    avaliar('globalThis.__saidaPrevia = null; globalThis.__erroPrevia = null; __catPrevia.executar().then(valor => { globalThis.__saidaPrevia = JSON.stringify(valor); }, erro => { globalThis.__erroPrevia = String(erro); });');
    let rodadas = 0;
    while (ambiente.hasPendingJob()) {
      if (++rodadas > 2000 || Date.now() > prazo) throw new Falha('tempoEsgotado');
      const resultado = ambiente.executePendingJobs(1); if (resultado.error) { resultado.error.dispose(); throw new Falha('execucaoFalhou'); }
    }
    const erro = contexto.getProp(contexto.global, '__erroPrevia').consume(contexto.dump); if (erro) throw new Falha('execucaoFalhou', { detalhe: String(erro) });
    const texto = contexto.getProp(contexto.global, '__saidaPrevia').consume(contexto.dump); if (typeof texto !== 'string') throw new Falha('promessaPendente');
    if (Buffer.byteLength(texto) > 1024 * 1024) throw new Falha('tamanho');
    const uso = ambiente.computeMemoryUsage().consume(contexto.dump);
    return { ...(ocultarSegredos(JSON.parse(texto)) as ResultadoPrevia), duracao: Date.now() - inicio, memoria: Number(uso?.memory_used_size ?? 0) };
  } finally { contexto.dispose(); ambiente.dispose(); }
}
