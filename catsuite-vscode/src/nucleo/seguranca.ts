import { createHash as criarHash, generateKeyPairSync as gerarPar, createPrivateKey as criarChavePrivada, createPublicKey as criarChavePublica, sign as assinar, verify as verificar, randomBytes as bytesAleatorios, createCipheriv as criarCifrador, createDecipheriv as criarDecifrador } from 'node:crypto';
import { argon2id } from 'hash-wasm';
import { Falha, Objeto } from './contratos';
export function hash(bytes: Uint8Array | string): string { return criarHash('sha256').update(bytes).digest('hex'); }
export function caminhoSeguro(caminho: string): boolean { return caminho.length > 0 && caminho.length <= 200 && !/[\\:\x00-\x1f]/.test(caminho) && !caminho.startsWith('/') && caminho.split('/').every(parte => parte !== '' && parte !== '.' && parte !== '..' && !['__proto__', 'constructor', 'prototype'].includes(parte)); }
export function numeroDecimal(valor: number): string {
  if (!Number.isFinite(valor) || Number.isInteger(valor) && !Number.isSafeInteger(valor)) throw new Falha('numeroInseguro');
  const texto = String(valor); if (!/[eE]/.test(texto)) return texto;
  const [mantissa = '', expoente = '0'] = texto.toLowerCase().split('e');
  const sinal = mantissa.startsWith('-') ? '-' : ''; const partes = mantissa.replace('-', '').split('.');
  const digitos = partes.join(''); const posicao = (partes[0]?.length ?? 0) + Number(expoente);
  return sinal + (posicao <= 0 ? '0.' + '0'.repeat(-posicao) + digitos : posicao >= digitos.length ? digitos + '0'.repeat(posicao - digitos.length) : digitos.slice(0, posicao) + '.' + digitos.slice(posicao));
}
export function canonico(valor: unknown, profundidade = 0): string {
  if (profundidade > 64) throw new Falha('profundidade');
  if (valor === null) return 'null';
  if (typeof valor === 'number') return numeroDecimal(valor);
  if (typeof valor === 'string' || typeof valor === 'boolean') return JSON.stringify(valor);
  if (Array.isArray(valor)) return '[' + valor.map(item => canonico(item, profundidade + 1)).join(',') + ']';
  if (typeof valor === 'object') return '{' + Object.keys(valor).sort().map(chave => JSON.stringify(chave) + ':' + canonico((valor as Objeto)[chave], profundidade + 1)).join(',') + '}';
  throw new Falha('jsonInvalido');
}
export function criarIdentidade(): { privada: string; publica: string; impressao: string } {
  const par = gerarPar('ed25519'); const privada = par.privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64');
  const publica = par.publicKey.export({ type: 'spki', format: 'der' }).subarray(-32).toString('base64');
  return { privada, publica, impressao: hash(Buffer.from(publica, 'base64')) };
}
export function assinarDocumento(documento: Objeto, privada: string): Objeto {
  const copia = structuredClone(documento); delete copia.signature;
  const chave = criarChavePrivada({ key: Buffer.from(privada, 'base64'), format: 'der', type: 'pkcs8' });
  const publica = criarChavePublica(chave).export({ format: 'der', type: 'spki' }).subarray(-32);
  const valor = assinar(null, Buffer.from(canonico(copia)), chave);
  return { ...copia, signature: { algorithm: 'Ed25519', publicKey: publica.toString('base64'), value: valor.toString('base64') } };
}
export function verificarAssinatura(documento: Objeto): { estado: 'valida' | 'invalida' | 'ausente'; impressao?: string } {
  if (!documento.signature) return { estado: 'ausente' };
  try {
    const s = documento.signature; if (s.algorithm !== 'Ed25519' || typeof s.publicKey !== 'string' || typeof s.value !== 'string') return { estado: 'invalida' };
    const publica = Buffer.from(s.publicKey, 'base64'); const assinatura = Buffer.from(s.value, 'base64');
    if (publica.length !== 32 || assinatura.length !== 64 || publica.toString('base64') !== s.publicKey || assinatura.toString('base64') !== s.value) return { estado: 'invalida' };
    const chave = criarChavePublica({ key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), publica]), type: 'spki', format: 'der' });
    const copia = { ...documento }; delete copia.signature;
    return { estado: verificar(null, Buffer.from(canonico(copia)), chave, assinatura) ? 'valida' : 'invalida', impressao: hash(publica) };
  } catch { return { estado: 'invalida' }; }
}
export function selado(bytes: Uint8Array): boolean { return Buffer.from(bytes.subarray(0, 8)).toString('ascii') === 'CATSEAL2'; }
async function derivar(senha: string, salt: Buffer): Promise<Buffer> { return Buffer.from(await argon2id({ password: senha, salt, parallelism: 1, iterations: 3, memorySize: 65536, hashLength: 32, outputType: 'binary' })); }
export async function proteger(bytes: Buffer, senha: string): Promise<Buffer> {
  if (Buffer.byteLength(senha) < 12 || Buffer.byteLength(senha) > 1024 || bytes.length > 64 * 1024 * 1024) throw new Falha('senhaLimite');
  const salt = bytesAleatorios(16); const nonce = bytesAleatorios(12); const cabecalho = Buffer.alloc(48);
  cabecalho.write('CATSEAL2', 0, 'ascii'); cabecalho.writeInt32BE(2, 8); cabecalho.writeInt32BE(3, 12); cabecalho.writeInt32BE(64, 16); salt.copy(cabecalho, 20); nonce.copy(cabecalho, 36);
  const chave = await derivar(senha, salt);
  try { const cifra = criarCifrador('aes-256-gcm', chave, nonce); cifra.setAAD(cabecalho); return Buffer.concat([cabecalho, cifra.update(bytes), cifra.final(), cifra.getAuthTag()]); }
  finally { chave.fill(0); }
}
export async function abrirProtegido(bytes: Buffer, senha: string): Promise<Buffer> {
  if (!selado(bytes)) return bytes;
  if (bytes.length < 64 || bytes.length > 64 * 1024 * 1024 + 64) throw new Falha('tamanho');
  if (bytes.readInt32BE(8) !== 2 || bytes.readInt32BE(12) !== 3 || bytes.readInt32BE(16) !== 64) throw new Falha('parametrosCripto');
  if (Buffer.byteLength(senha) < 1 || Buffer.byteLength(senha) > 1024) throw new Falha('senhaLimite');
  const chave = await derivar(senha, bytes.subarray(20, 36));
  try { const cifra = criarDecifrador('aes-256-gcm', chave, bytes.subarray(36, 48)); cifra.setAAD(bytes.subarray(0, 48)); cifra.setAuthTag(bytes.subarray(-16)); return Buffer.concat([cifra.update(bytes.subarray(48, -16)), cifra.final()]); }
  catch { throw new Falha('senhaIncorreta'); } finally { chave.fill(0); }
}
export function ocultarSegredos(valor: unknown, profundidade = 0): unknown {
  if (profundidade > 20) return '…';
  if (Array.isArray(valor)) return valor.slice(0, 1000).map(item => ocultarSegredos(item, profundidade + 1));
  if (valor && typeof valor === 'object') { const o = valor as Objeto; if (typeof o.name === 'string' && /^(authorization|proxy-authorization|cookie|set-cookie|x-api-key)$/i.test(o.name)) return { ...o, value: '[OCULTO]' }; return Object.fromEntries(Object.entries(o).map(([k, v]) => [k, /password|senha|privatekey|apikey|access.?token|refresh.?token|secret/i.test(k) ? '[OCULTO]' : ocultarSegredos(v, profundidade + 1)])); }
  if (typeof valor === 'string') return valor.slice(0, 32768).replace(/Bearer\s+[^\s"']+/gi, 'Bearer [OCULTO]').replace(/-----BEGIN[\s\S]*?PRIVATE KEY-----[\s\S]*?-----END[\s\S]*?PRIVATE KEY-----/g, '[OCULTO]');
  return valor;
}

export function exigirConfianca(confiavel: boolean): void { if (!confiavel) throw new Falha('confiancaNecessaria'); }
