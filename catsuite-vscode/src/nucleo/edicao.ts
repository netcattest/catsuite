import { randomUUID as identidadeAleatoria } from 'node:crypto';
import { Falha, limites, Objeto } from './contratos';
import { selado } from './seguranca';
import { verificarPacote } from './pacotes';
export function classificarCatPlug(bytes: Uint8Array): 'script' | 'pacote' | 'invalido' {
  if (selado(bytes) || bytes[0] === 0x50 && bytes[1] === 0x4b && [3,5,7].includes(bytes[2] ?? 0)) return 'pacote';
  if (bytes.length > limites.codigo) return 'invalido';
  try { const texto = new TextDecoder('utf-8',{fatal:true}).decode(bytes); return /[\x00-\x08\x0b\x0c\x0e-\x1f]/.test(texto) ? 'invalido' : 'script'; } catch { return 'invalido'; }
}
export async function prepararCopiaEditavel(bytes: Buffer): Promise<{manifesto: Objeto; arquivos: Record<string,Buffer>}> {
  const pacote = await verificarPacote(bytes);
  for(const [nome,conteudo] of Object.entries(pacote.arquivos)) {
    if (/(?:^|\/)(?:\.git|\.vscode|\.ssh|node_modules|\.env[^/]*)(?:\/|$)|\.(?:catkey|pem|key|p12|pfx)$/i.test(nome) || ['catsuite.projeto.json','jsconfig.json','package.json','package-lock.json'].includes(nome.toLowerCase()) || /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|(?:ghp_|github_pat_)[A-Za-z0-9_]{20,}|AKIA[A-Z0-9]{16}/.test(conteudo.toString('utf8'))) throw new Falha('arquivoPrivado',{arquivo:nome});
  }
  const manifesto = structuredClone(pacote.manifesto); delete manifesto.signature; manifesto.parentRevision = manifesto.revisionId ?? null; manifesto.revisionId = identidadeAleatoria(); manifesto.lineageId ??= identidadeAleatoria(); manifesto.hashes = {};
  manifesto.origin = {kind:'catsuite-studio-edit',version:'1.2.0',parentRevision:pacote.manifesto.revisionId ?? null,authorFingerprint:pacote.assinatura.impressao ?? null,sourceSignature:pacote.assinatura.estado,verified:false};
  return {manifesto,arquivos:pacote.arquivos};
}
