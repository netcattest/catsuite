import { promises as arquivos } from 'node:fs';
import caminho from 'node:path';
import { randomUUID as identidadeAleatoria } from 'node:crypto';
import { fromBuffer, Entry } from 'yauzl';
import { ZipFile } from 'yazl';
import { Falha, limites, Objeto, Projeto, Problema } from './contratos';
import { caminhoSeguro, hash, assinarDocumento, verificarAssinatura, selado } from './seguranca';
import { interpretarJson, validarManifesto, analisarCodigo, validarFluxo } from './validacao';
export async function lerArquivoSeguro(nome: string, maximo: number): Promise<Buffer> {
  const estado = await arquivos.lstat(nome); if (!estado.isFile() || estado.isSymbolicLink() || estado.size > maximo) throw new Falha('tamanho');
  const descritor = await arquivos.open(nome, 'r');
  try { const real = await descritor.stat(); if (!real.isFile() || real.size > maximo || real.ino !== estado.ino || real.dev !== estado.dev) throw new Falha('tamanho'); const bytes = await descritor.readFile(); if (bytes.length > maximo) throw new Falha('tamanho'); return bytes; } finally { await descritor.close(); }
}
export async function lerDentro(pasta: string, relativo: string, maximo: number): Promise<Buffer> {
  if (!caminhoSeguro(relativo)) throw new Falha('caminhoInvalido', { caminho: relativo });
  const raiz = await arquivos.realpath(pasta); const alvo = caminho.join(raiz, ...relativo.split('/')); const real = await arquivos.realpath(alvo);
  if (real !== alvo || caminho.relative(raiz, real).startsWith('..') || caminho.isAbsolute(caminho.relative(raiz, real))) throw new Falha('caminhoInvalido', { caminho: relativo });
  return lerArquivoSeguro(real, maximo);
}
export async function lerProjeto(pasta: string): Promise<Projeto> {
  const manifesto = interpretarJson((await lerDentro(pasta, 'manifest.json', limites.manifesto)).toString('utf8'));
  const configuracao = interpretarJson((await lerDentro(pasta, 'catsuite.projeto.json', limites.manifesto)).toString('utf8'));
  if (configuracao.format !== 'catsuite-project' || configuracao.version !== 1 || !Array.isArray(configuracao.files) || configuracao.files.length > limites.arquivos) throw new Falha('projetoInvalido');
  const nomes = configuracao.files as unknown[]; if (nomes.some(n => typeof n !== 'string') || new Set(nomes).size !== nomes.length) throw new Falha('caminhoInvalido');
  const conteudos: Record<string, Buffer> = Object.create(null); let total = 0;
  for (const nome of nomes as string[]) {
    if (/^(?:manifest\.json|catsuite\.projeto\.json)$/.test(nome) || /(?:^|\/)(?:\.env[^/]*|\.git|\.ssh|node_modules)(?:\/|$)|\.(?:pem|key|catkey|p12|pfx)$/i.test(nome)) throw new Falha('arquivoPrivado', { arquivo: nome });
    const bytes = await lerDentro(pasta, nome, limites.arquivo); total += bytes.length; if (total > limites.expandido) throw new Falha('tamanho'); if (/-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|(?:ghp_|github_pat_)[A-Za-z0-9_]{20,}|AKIA[A-Z0-9]{16}/.test(bytes.toString('utf8'))) throw new Falha('segredoEncontrado'); conteudos[nome] = bytes;
  }
  if (!conteudos[manifesto.entry]) throw new Falha('entradaInvalida');
  const codigo = new TextDecoder('utf-8', { fatal: true }).decode(conteudos[manifesto.entry]);
  const problemas = [...validarManifesto(manifesto), ...analisarCodigo(codigo, manifesto)];
  for (const [nome, bytes] of Object.entries(conteudos)) if (manifesto.hashes?.[nome] && manifesto.hashes[nome] !== hash(bytes)) problemas.push({ codigo: 'hashDesatualizado', caminho: 'hashes.' + nome, gravidade: 'aviso' });
  if (!Object.keys(manifesto.hashes ?? {}).length) problemas.push({ codigo: 'rascunho', caminho: 'hashes', gravidade: 'aviso' });
  return { pasta, manifesto, arquivos: conteudos, codigo, problemas };
}
export function descompactar(bytes: Buffer): Promise<Record<string, Buffer>> {
  if (bytes.length > limites.pacote || !bytes.length) return Promise.reject(new Falha('tamanho'));
  return new Promise((concluir, rejeitar) => {
    fromBuffer(bytes, { lazyEntries: true, autoClose: true, validateEntrySizes: true, strictFileNames: true }, (erro, zip) => {
      if (erro || !zip) { rejeitar(new Falha('pacoteInvalido')); return; }
      const resultado: Record<string, Buffer> = Object.create(null); let total = 0; let contador = 0; let falhou = false;
      const falhar = (falha: unknown) => { if (falhou) return; falhou = true; zip.close(); rejeitar(falha instanceof Falha ? falha : new Falha('pacoteInvalido')); };
      zip.on('error', falhar); zip.on('end', () => { if (!falhou) concluir(resultado); });
      zip.on('entry', (entrada: Entry) => {
        const nome = entrada.fileName; const modo = (entrada.externalFileAttributes >>> 16) & 0xf000;
        if (!caminhoSeguro(nome) || Object.hasOwn(resultado, nome) || modo === 0xa000 || modo === 0x4000 || entrada.isEncrypted()) { falhar(new Falha('caminhoInvalido', { caminho: nome })); return; }
        if (++contador > limites.arquivos || entrada.uncompressedSize > limites.arquivo || total + entrada.uncompressedSize > limites.expandido) { falhar(new Falha('tamanho')); return; }
        zip.openReadStream(entrada, (erroLeitura, fluxo) => {
          if (erroLeitura || !fluxo) { falhar(new Falha('pacoteInvalido')); return; }
          const partes: Buffer[] = []; let tamanho = 0;
          fluxo.on('error', falhar); fluxo.on('data', (parte: Buffer) => { tamanho += parte.length; total += parte.length; if (tamanho > limites.arquivo || total > limites.expandido) { fluxo.destroy(); falhar(new Falha('tamanho')); } else partes.push(parte); });
          fluxo.on('end', () => { if (!falhou) { resultado[nome] = Buffer.concat(partes); zip.readEntry(); } });
        });
      }); zip.readEntry();
    });
  });
}
export async function verificarPacote(bytes: Buffer): Promise<{ manifesto: Objeto; arquivos: Record<string, Buffer>; assinatura: ReturnType<typeof verificarAssinatura> }> {
  if (selado(bytes)) throw new Falha('arquivoProtegido');
  const conteudos = await descompactar(bytes); const entrada = conteudos['manifest.json']; if (!entrada || entrada.length > limites.manifesto) throw new Falha('manifestoAusente');
  const manifesto = interpretarJson(new TextDecoder('utf-8', { fatal: true }).decode(entrada)); delete conteudos['manifest.json'];
  const erros = validarManifesto(manifesto).filter(p => p.gravidade === 'erro'); if (erros.length) throw new Falha(erros[0]!.codigo, erros[0]!.argumentos);
  if (!conteudos[manifesto.entry] || conteudos[manifesto.entry]!.length > limites.codigo) throw new Falha('entradaInvalida');
  new TextDecoder('utf-8', { fatal: true }).decode(conteudos[manifesto.entry]);
  if (Object.keys(manifesto.hashes).length !== Object.keys(conteudos).length || Object.entries(conteudos).some(([nome, b]) => manifesto.hashes[nome] !== hash(b))) throw new Falha('hashInvalido');
  return { manifesto, arquivos: conteudos, assinatura: verificarAssinatura(manifesto) };
}
export async function compactar(manifesto: Objeto, arquivos: Record<string, Buffer>): Promise<Buffer> {
  const zip = new ZipFile(); const partes: Buffer[] = []; let tamanho = 0;
  const promessa = new Promise<Buffer>((resolver, rejeitar) => { zip.outputStream.on('data', (b: Buffer) => { tamanho += b.length; if (tamanho > limites.pacote) { (zip.outputStream as import('node:stream').Readable).destroy(); rejeitar(new Falha('tamanho')); } else partes.push(b); }); zip.outputStream.on('error', rejeitar); zip.outputStream.on('end', () => resolver(Buffer.concat(partes))); });
  const opcoes = { mtime: new Date('2026-01-01T00:00:00Z'), mode: 0o100644 };
  zip.addBuffer(Buffer.from(JSON.stringify(manifesto, null, 2)), 'manifest.json', opcoes);
  for (const nome of Object.keys(arquivos).sort()) { if (!caminhoSeguro(nome) || nome === 'manifest.json') throw new Falha('caminhoInvalido'); zip.addBuffer(arquivos[nome]!, nome, opcoes); }
  zip.end(); return promessa;
}
export async function criarPacote(projeto: Projeto, privada: string): Promise<Buffer> {
  if (projeto.problemas.some(p => p.gravidade === 'erro')) throw new Falha('validacaoFalhou');
  const m = structuredClone(projeto.manifesto); delete m.signature; m.formatVersion = 2; m.requiresSdk = '1.4.0'; m.parentRevision = m.revisionId; m.revisionId = identidadeAleatoria(); m.lineageId ??= identidadeAleatoria();
  m.hashes = Object.fromEntries(Object.entries(projeto.arquivos).map(([n, b]) => [n, hash(b)]));
  m.origin = { kind: 'catsuite-studio', version: '1.2.0', parentRevision: projeto.manifesto.revisionId ?? null, verified: false };
  const assinado = assinarDocumento(m, privada); const bytes = await compactar(assinado, projeto.arquivos); await verificarPacote(bytes); return bytes;
}
export async function gravarAtomico(alvo: string, bytes: Buffer): Promise<void> {
  const temporario = caminho.join(caminho.dirname(alvo), '.' + caminho.basename(alvo) + '.' + identidadeAleatoria() + '.tmp');
  try { await arquivos.writeFile(temporario, bytes, { flag: 'wx', mode: 0o600 }); await arquivos.rename(temporario, alvo); } finally { await arquivos.rm(temporario, { force: true }); }
}
export async function inspecionar(bytes: Buffer, extensao: string): Promise<Objeto> {
  if (selado(bytes)) return { tipo: 'protegido', tamanho: bytes.length, bloqueado: true };
  if (extensao === '.catplug') { const p = await verificarPacote(bytes); return { tipo: 'catplug', tamanho: bytes.length, manifesto: p.manifesto, assinatura: p.assinatura, arquivos: Object.entries(p.arquivos).map(([nome, b]) => ({ nome, tamanho: b.length, sha256: hash(b) })), problemas: analisarCodigo(p.arquivos[p.manifesto.entry]!.toString('utf8'), p.manifesto) }; }
  if (bytes.length > (extensao === '.catflow' ? limites.fluxo : 64 * 1024 * 1024)) throw new Falha('tamanho');
  const documento = interpretarJson(new TextDecoder('utf-8', { fatal: true }).decode(bytes)); const problemas: Problema[] = extensao === '.catflow' ? validarFluxo(documento) : [];
  if (extensao === '.catdata' && (documento.format !== 'catdata' || ![1, 2, 3, 4].includes(documento.formatVersion))) throw new Falha('versaoIncompativel');
  const assinatura = verificarAssinatura(documento); if (assinatura.estado === 'invalida') throw new Falha('assinaturaInvalida');
  return { tipo: extensao.slice(1), tamanho: bytes.length, documento, assinatura, problemas };
}
