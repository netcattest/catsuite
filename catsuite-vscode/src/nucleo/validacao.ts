import { parseTree, ParseError, Node as NoJson, getNodeValue } from 'jsonc-parser';
import { parse } from 'acorn';
import { domainToASCII as dominioAscii } from 'node:url';
import { isIP as tipoIp } from 'node:net';
import { api, Falha, Objeto, Problema, permissoes, tiposArtefato, tiposBloco, limites } from './contratos';
import { caminhoSeguro, canonico, verificarAssinatura } from './seguranca';
export function interpretarJson(texto: string): Objeto {
  const erros: ParseError[] = []; const raiz = parseTree(texto, erros, { allowTrailingComma: false, disallowComments: true });
  if (!raiz || erros.length || raiz.type !== 'object') throw new Falha('jsonInvalido');
  function percorrer(no: NoJson, profundidade = 0): void {
    if (profundidade > 64) throw new Falha('profundidade');
    if (no.type === 'object') { const vistos = new Set<string>(); for (const item of no.children ?? []) { const nome = item.children?.[0]?.value as string; if (vistos.has(nome)) throw new Falha('chaveDuplicada', { chave: nome }); if (['__proto__', 'constructor', 'prototype'].includes(nome)) throw new Falha('chaveReservada', { chave: nome }); vistos.add(nome); } }
    for (const filho of no.children ?? []) percorrer(filho, profundidade + 1);
  }
  percorrer(raiz); const valor = getNodeValue(raiz) as Objeto; canonico(valor); return valor;
}
export function normalizarDestino(entrada: string): string {
  if (!entrada || entrada.length > 2048 || /[\s\\\x00-\x1f]/.test(entrada) || entrada === '*' || entrada.includes('%')) throw new Falha('destinoInvalido', { destino: entrada });
  const wildcard = entrada.startsWith('*.'); const texto = wildcard ? entrada.slice(2) : entrada;
  let url: URL;
  try { url = new URL(texto.includes('://') ? texto : 'https://' + (tipoIp(texto) === 6 ? '[' + texto + ']' : texto)); } catch { throw new Falha('destinoInvalido', { destino: entrada }); }
  if (!['https:', 'http:'].includes(url.protocol) || url.username || url.password || url.search || url.hash) throw new Falha('destinoInvalido', { destino: entrada });
  const host = url.hostname.replace(/^\[|\]$/g, ''); const ip = tipoIp(host);
  if (!ip && (!dominioAscii(host) || host.split('.').some(p => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(p)))) throw new Falha('destinoInvalido', { destino: entrada });
  const originalHost = texto.replace(/^https?:\/\//i, '').split('/')[0] ?? '';
  if (ip === 4 && originalHost.split(':')[0] !== host) throw new Falha('destinoAmbiguo', { destino: entrada });
  if (wildcard && ip) throw new Falha('destinoInvalido', { destino: entrada });
  if (url.port && (Number(url.port) < 1 || Number(url.port) > 65535)) throw new Falha('destinoInvalido', { destino: entrada });
  return (entrada.includes('://') ? url.protocol + '//' : '') + (wildcard ? '*.' : '') + url.host + (url.pathname === '/' ? '' : url.pathname);
}
export function validarManifesto(m: Objeto): Problema[] {
  const lista: Problema[] = []; const erro = (codigo: string, caminho: string, argumentos?: Record<string, string | number>) => lista.push({ codigo, caminho, gravidade: 'erro', argumentos });
  if (![1, 2].includes(m.formatVersion) || m.apiVersion !== 1) erro('versaoIncompativel', 'formatVersion');
  if (!/^[a-z][a-z0-9.-]{2,63}$/.test(m.id ?? '')) erro('identidadeInvalida', 'id');
  if (!/^\d+\.\d+\.\d+$/.test(m.version ?? '')) erro('versaoIncompativel', 'version');
  if (typeof m.author !== 'string' || !m.author.trim()) erro('campoObrigatorio', 'author', { campo: 'author' });
  for (const campo of ['name', 'description']) for (const idioma of ['pt-BR', 'en']) if (typeof m[campo]?.[idioma] !== 'string' || !m[campo][idioma].trim()) erro('traducaoAusente', campo + '.' + idioma, { idioma });
  if (typeof m.entry !== 'string' || !caminhoSeguro(m.entry) || !m.entry.endsWith('.js')) erro('entradaInvalida', 'entry');
  if (!Array.isArray(m.permissions) || m.permissions.some((p: unknown) => !permissoes.includes(p as any)) || new Set(m.permissions).size !== m.permissions.length) erro('permissaoInvalida', 'permissions');
  for (const campo of ['targets', 'externalHosts']) {
    if (!Array.isArray(m[campo]) || m[campo].length > 100) erro('destinoInvalido', campo);
    else for (const destino of m[campo]) { try { if (typeof destino !== 'string') throw new Falha('destinoInvalido'); normalizarDestino(destino); } catch (e) { erro(e instanceof Falha ? e.codigo : 'destinoInvalido', campo, { destino: String(destino) }); } }
  }
  if (m.formatVersion === 2) {
    for (const campo of ['revisionId', 'lineageId']) if (!/^[a-f\d]{8}(-[a-f\d]{4}){3}-[a-f\d]{12}$/i.test(m[campo] ?? '')) erro('revisaoInvalida', campo);
    if (!['1.0.0', '1.1.0', '1.2.0', '1.3.0', '1.4.0'].includes(m.requiresSdk ?? '1.1.0')) erro('versaoIncompativel', 'requiresSdk');
  }
  if (!m.hashes || typeof m.hashes !== 'object' || Array.isArray(m.hashes)) erro('hashInvalido', 'hashes');
  else for (const [nome, valor] of Object.entries(m.hashes)) if (!caminhoSeguro(nome) || !/^[a-f0-9]{64}$/.test(String(valor))) erro('hashInvalido', 'hashes.' + nome);
  if (m.signature && verificarAssinatura(m).estado !== 'valida') erro('assinaturaInvalida', 'signature');
  if (m.settingsSchema && typeof m.settingsSchema === 'object' && !Array.isArray(m.settingsSchema)) for (const [chave, campo] of Object.entries(m.settingsSchema as Objeto)) {
    if (!campo || typeof campo !== 'object') { erro('configuracaoInvalida', 'settingsSchema.' + chave); continue; }
    if (!/^[a-zA-Z0-9_.-]{1,64}$/.test(chave) || !['string', 'boolean', 'integer', 'number', 'secret', 'credential'].includes(campo.type ?? 'string')) erro('configuracaoInvalida', 'settingsSchema.' + chave);
    for (const idioma of ['pt-BR', 'en']) if (!campo.title?.[idioma]) erro('traducaoAusente', 'settingsSchema.' + chave + '.title', { idioma });
  }
  if (Buffer.byteLength(JSON.stringify(m)) > limites.manifesto) erro('tamanho', '');
  return lista;
}
function caminhoApi(no: any): string | undefined {
  if (no?.type === 'Identifier') return no.name;
  if (no?.type === 'MemberExpression' && !no.computed) { const base = caminhoApi(no.object); return base && base + '.' + no.property.name; }
  return undefined;
}
export function analisarCodigo(codigo: string, manifesto: Objeto): Problema[] {
  const problemas: Problema[] = []; const declaradas = new Set(manifesto.permissions ?? []);
  const adicionar = (chave: string, no: any, args?: Record<string, string | number>, gravidade: 'erro' | 'aviso' = 'erro') => problemas.push({ codigo: chave, gravidade, caminho: manifesto.entry ?? '', linha: no.loc?.start.line ?? 1, coluna: no.loc?.start.column ?? 0, argumentos: args });
  if (Buffer.byteLength(codigo) > limites.codigo) return [{ codigo: 'tamanho', caminho: manifesto.entry, gravidade: 'erro' }];
  let arvore: any;
  try { arvore = parse(codigo, { ecmaVersion: 2024, sourceType: 'script', locations: true }); } catch (erro: any) { return [{ codigo: 'sintaxe', argumentos: { detalhe: String(erro.message) }, gravidade: 'erro', caminho: manifesto.entry, linha: erro.loc?.line ?? 1, coluna: erro.loc?.column ?? 0 }]; }
  function visitar(no: any, pai?: any, modificacao = false): void {
    if (!no || typeof no !== 'object') return;
    if (no.type === 'CallExpression' || no.type === 'NewExpression') {
      const nome = caminhoApi(no.callee);
      if (nome && ['require', 'eval', 'Function', 'fetch', 'XMLHttpRequest', 'WebSocket'].includes(nome)) adicionar('apiIndisponivel', no, { api: nome });
      if (nome?.startsWith('cat.')) {
        const definicao = api[nome.slice(4)];
        if (!definicao) adicionar('apiDesconhecida', no, { api: nome }, 'aviso');
        if (definicao?.permissao && !declaradas.has(definicao.permissao)) adicionar('permissaoAusente', no, { permissao: definicao.permissao, api: nome });
        if (modificacao && /^cat\.(http\.(send|cancel)|storage|external|connectors|ui|findings|commands|laboratory)/.test(nome)) adicionar('handlerSincrono', no);
      }
      if (nome === 'cat.proxy.onRequest' || nome === 'cat.proxy.onResponse') {
        const handler = no.arguments?.[0]; if (handler?.async) adicionar('handlerSincrono', handler);
        if (handler?.body) visitar(handler.body, handler, true);
      }
    }
    if (no.type === 'Identifier' && ['process', 'global', 'Buffer', 'document', 'window'].includes(no.name) && !(pai?.type === 'MemberExpression' && pai.property === no && !pai.computed) && !(pai?.type === 'Property' && pai.key === no && !pai.computed)) adicionar('apiIndisponivel', no, { api: no.name });
    if (no.type === 'MemberExpression' && no.computed && caminhoApi(no.object)?.startsWith('cat')) adicionar('apiDinamica', no, undefined, 'aviso');
    for (const [chave, filho] of Object.entries(no)) {
      if (['loc', 'start', 'end'].includes(chave)) continue;
      if ((no.type === 'CallExpression') && /^cat\.proxy\.(onRequest|onResponse)$/.test(caminhoApi(no.callee) ?? '') && chave === 'arguments') continue;
      if (Array.isArray(filho)) for (const item of filho) visitar(item, no, modificacao); else if (filho && typeof filho === 'object') visitar(filho, no, modificacao);
    }
  }
  visitar(arvore);
  if (/-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|(?:ghp_|github_pat_)[A-Za-z0-9_]{20,}|AKIA[A-Z0-9]{16}/.test(codigo)) problemas.push({ codigo: 'segredoEncontrado', caminho: manifesto.entry, gravidade: 'erro' });
  return problemas;
}
export function validarFluxo(fluxo: Objeto): Problema[] {
  const problemas: Problema[] = []; const erro = (codigo: string, caminho: string, argumentos?: Record<string, string | number>) => problemas.push({ codigo, caminho, gravidade: 'erro', argumentos });
  if (fluxo.format !== 'catflow' || ![2, 3, 4, 5].includes(fluxo.formatVersion)) erro('versaoIncompativel', 'formatVersion');
  if (!Array.isArray(fluxo.nodes) || !Array.isArray(fluxo.edges)) { erro('fluxoInvalido', 'nodes'); return problemas; }
  if (fluxo.nodes.some((no: unknown) => !no || typeof no !== 'object' || Array.isArray(no)) || fluxo.edges.some((c: unknown) => !c || typeof c !== 'object' || Array.isArray(c))) { erro('fluxoInvalido', 'nodes'); return problemas; }
  const nos = fluxo.nodes as Objeto[]; const conexoes = fluxo.edges as Objeto[];
  if (nos.length > 128 || conexoes.length > 256 || Buffer.byteLength(JSON.stringify(fluxo)) > limites.fluxo) erro('tamanho', 'nodes');
  const ids = new Set(nos.map(no => no.id)); if (ids.size !== nos.length) erro('blocoDuplicado', 'nodes');
  for (const no of nos) {
    if (!tiposBloco.includes(no.kind) || typeof no.id !== 'string' || !Array.isArray(no.inputs) || !Array.isArray(no.outputs) || [...(Array.isArray(no.inputs) ? no.inputs : []), ...(Array.isArray(no.outputs) ? no.outputs : [])].some(t => !tiposArtefato.includes(t))) erro('blocoInvalido', 'nodes');
    if (no.kind === 'extension' && (!no.extension || !no.step)) erro('blocoInvalido', 'nodes');
  }
  const duplicadas = new Set<string>();
  for (const c of conexoes) {
    const origem = nos.find(no => no.id === c.from); const destino = nos.find(no => no.id === c.to);
    if (!origem || !destino || origem === destino || !['', 'true', 'false'].includes(c.when ?? '') || c.when && origem.kind !== 'condition') { erro('conexaoInvalida', 'edges'); continue; }
    const chave = c.from + ':' + c.to + ':' + (c.when ?? ''); if (duplicadas.has(chave)) erro('conexaoInvalida', 'edges'); duplicadas.add(chave);
    if (!(Array.isArray(origem.outputs) ? origem.outputs : []).some((tipo: string) => Array.isArray(destino.inputs) && destino.inputs.includes(tipo)) && destino.kind !== 'join') erro('tipoIncompativel', 'edges', { origem: c.from, destino: c.to });
  }
  const restantes = new Set(ids); let avancou = true;
  while (restantes.size && avancou) { avancou = false; for (const id of [...restantes]) if (conexoes.filter(c => c.to === id).every(c => !restantes.has(c.from))) { restantes.delete(id); avancou = true; } }
  if (restantes.size) erro('ciclo', 'edges');
  for (const destino of Array.isArray(fluxo.targets) ? fluxo.targets : []) try { normalizarDestino(destino); } catch { erro('destinoInvalido', 'targets', { destino: String(destino) }); }
  if (fluxo.signature && verificarAssinatura(fluxo).estado !== 'valida') erro('assinaturaInvalida', 'signature');
  if (!fluxo.signature) problemas.push({ codigo: 'semAssinatura', caminho: 'signature', gravidade: 'aviso' });
  return problemas;
}
