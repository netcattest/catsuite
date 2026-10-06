import { randomUUID as novaIdentidade } from 'node:crypto';
import { Objeto } from './contratos';
export const modelos = ['painel', 'analise', 'headers', 'fluxo', 'parser'] as const;
export type Modelo = typeof modelos[number];
export function criarModelo(modelo: Modelo, nome: string, autor: string, id: string): { manifesto: Objeto; codigo: string; projeto: Objeto; fixture: Objeto } {
  const titulo = { 'pt-BR': nome, en: nome };
  const descricao = { 'pt-BR': 'Extensão criada no CatSuite Studio.', en: 'Extension created in CatSuite Studio.' };
  const nomeJson = JSON.stringify(titulo);
  const fontes: Record<Modelo, string> = {
    painel: `const titulo = ${nomeJson};
cat.commands.register('painel.executar', titulo, async () => {
  const armazenado = await cat.storage.get('execucoes');
  const total = (typeof armazenado === 'number' ? armazenado : 0) + 1;
  await cat.storage.set('execucoes', total);
  cat.ui.update('painel.principal', [
    { type: 'text', text: { 'pt-BR': 'Execuções: ' + total, en: 'Runs: ' + total } },
    { type: 'button', label: { 'pt-BR': 'Executar', en: 'Run' }, command: 'painel.executar' }
  ]);
  return { total };
});
cat.ui.tab.register({ id: 'painel.principal', title: titulo, components: [
  { type: 'text', text: { 'pt-BR': 'Seu painel está pronto.', en: 'Your panel is ready.' } },
  { type: 'button', label: { 'pt-BR': 'Executar', en: 'Run' }, command: 'painel.executar' }
] });
`,
    analise: `cat.events.on('http.complete', async mensagem => {
  if (!mensagem.status || mensagem.headers.some(header => header.name.toLowerCase() === 'cache-control')) return;
  await cat.findings.add({
    fingerprint: 'cache:' + mensagem.url,
    title: { 'pt-BR': 'Cache-Control ausente', en: 'Missing Cache-Control' },
    description: { 'pt-BR': 'A resposta observada não declarou Cache-Control.', en: 'The observed response did not declare Cache-Control.' },
    severity: 'info', confidence: 'observed', url: mensagem.url,
    evidence: { response: mensagem }
  });
});
`,
    headers: `cat.proxy.onRequest(mensagem => {
  if (!['GET', 'HEAD'].includes(mensagem.method)) return mensagem;
  mensagem.headers = mensagem.headers.filter(header => header.name.toLowerCase() !== 'x-cat-lab');
  mensagem.headers.push({ name: 'X-Cat-Lab', value: 'studio' });
  return mensagem;
});
`,
    fluxo: `cat.pipeline.registerStep({
  id: 'fluxo.inspecionar', title: ${nomeJson}, inputs: ['http'], outputs: ['http', 'analysis']
}, async contexto => {
  for (const artefato of contexto.inputs) {
    if (contexto.signal.aborted) return;
    contexto.emit('http', artefato.data);
    const dados = JSON.parse(JSON.stringify(artefato.data));
    contexto.emit('analysis', { url: dados.url, status: dados.status || null });
  }
  await contexto.checkpoint({ etapa: 'concluida' });
  contexto.progress(1);
});
`,
    parser: `cat.parsers.register({
  id: 'parser.json', title: ${nomeJson}, mimeTypes: ['application/json'], inputs: ['http'], outputs: ['analysis']
}, contexto => {
  for (const artefato of contexto.inputs) {
    const dadosMensagem = JSON.parse(JSON.stringify(artefato.data));
    const corpo = dadosMensagem.body;
    if (!corpo || !corpo.available || !corpo.complete || corpo.truncated) continue;
    const dados = JSON.parse(cat.bytes.toText(corpo.bytes));
    contexto.emit('analysis', { campos: Object.keys(dados), url: dadosMensagem.url });
  }
  contexto.progress(1);
});
`
  };
  const permissao: Record<Modelo, string[]> = { painel: ['commands', 'ui.tab', 'storage'], analise: ['traffic.read', 'findings'], headers: ['traffic.modify'], fluxo: ['pipeline.step'], parser: ['parsers'] };
  const fixture = { id: 'fixture-studio', source: 'laboratory', session: 'studio', stage: 'response', url: 'https://api.aurora.test/api/perfil', method: 'GET', status: 200, reason: 'OK', time: 1791205200000, headers: [{ name: 'Content-Type', value: 'application/json' }], body: { bytes: Array.from(Buffer.from('{"nome":"Aurora","perfil":"ficticio"}')), complete: true, truncated: false, available: true, mutable: true } };
  return { manifesto: { formatVersion: 2, apiVersion: 1, requiresSdk: '1.4.0', id, version: '1.0.0', author: autor, entry: 'src/principal.js', revisionId: novaIdentidade(), lineageId: novaIdentidade(), name: titulo, description: descricao, permissions: permissao[modelo], targets: modelo === 'painel' ? [] : ['https://api.aurora.test'], externalHosts: [], settings: {}, hashes: {} }, codigo: fontes[modelo], projeto: { format: 'catsuite-project', version: 1, model: modelo, files: ['src/principal.js'], fixture: 'fixtures/resposta.json' }, fixture };
}
export function modeloFluxo(): Objeto { return { format: 'catflow', formatVersion: 3, id: novaIdentidade(), lineageId: novaIdentidade(), name: { 'pt-BR': 'Meu fluxo', en: 'My workflow' }, version: '1.0.0', author: 'Local', requiresSdk: '1.2.0', protection: 'PUBLIC', trigger: 'manual', laboratory: true, network: false, targets: ['https://api.aurora.test'], methods: ['GET', 'HEAD'], nodes: [{ id: 'captura', kind: 'capture', inputs: [], outputs: ['http'], config: {}, x: 80, y: 70 }, { id: 'relatorio', kind: 'report', inputs: ['http'], outputs: ['record'], config: {}, x: 80, y: 220 }], edges: [{ from: 'captura', to: 'relatorio' }] }; }
