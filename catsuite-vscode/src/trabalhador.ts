import { Worker } from 'node:worker_threads';
import { Falha } from './nucleo/contratos';
export function trabalhar<T>(arquivo: string, operacao: string, dados: unknown, cancelamento?: { onCancellationRequested: (callback: () => void) => { dispose(): void }; isCancellationRequested: boolean }): Promise<T> {
  return new Promise((resolver, rejeitar) => {
    if (cancelamento?.isCancellationRequested) { rejeitar(new Falha('cancelado')); return; }
    const worker = new Worker(arquivo, { resourceLimits: { maxOldGenerationSizeMb: 128, maxYoungGenerationSizeMb: 16, stackSizeMb: 4 } }); let terminou = false;
    const finalizar = (erro?: unknown, resultado?: T) => { if (terminou) return; terminou = true; clearTimeout(prazo); disposicao?.dispose(); void worker.terminate(); if (erro) rejeitar(erro); else resolver(resultado!); };
    const prazo = setTimeout(() => finalizar(new Falha('tempoEsgotado')), 20000);
    const disposicao = cancelamento?.onCancellationRequested(() => finalizar(new Falha('cancelado')));
    worker.once('error', () => finalizar(new Falha('execucaoFalhou')));
    worker.once('exit', () => { if (!terminou) finalizar(new Falha('execucaoFalhou')); });
    worker.once('message', mensagem => finalizar(mensagem.erro ? new Falha(mensagem.erro, mensagem.argumentos) : undefined, mensagem.resultado as T));
    worker.postMessage({ operacao, dados });
  });
}
