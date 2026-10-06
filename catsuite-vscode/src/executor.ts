import { parentPort } from 'node:worker_threads';
import { executarPrevia } from './nucleo/simulacao';
import { proteger, abrirProtegido } from './nucleo/seguranca';
import { Falha } from './nucleo/contratos';
parentPort?.on('message', async entrada => {
  try {
    let resultado: unknown;
    if (entrada.operacao === 'previa') resultado = await executarPrevia(entrada.dados);
    else if (entrada.operacao === 'proteger') resultado = await proteger(Buffer.from(entrada.dados.bytes), entrada.dados.senha);
    else if (entrada.operacao === 'abrir') resultado = await abrirProtegido(Buffer.from(entrada.dados.bytes), entrada.dados.senha);
    else throw new Falha('operacaoInvalida');
    parentPort?.postMessage({ resultado });
  } catch (erro) { parentPort?.postMessage({ erro: erro instanceof Falha ? erro.codigo : 'execucaoFalhou', argumentos: erro instanceof Falha ? erro.argumentos : {} }); }
});
