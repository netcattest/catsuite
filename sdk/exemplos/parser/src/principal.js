cat.parsers.register({
  id: 'parser.json', title: {"pt-BR":"Parser JSON","en":"Parser JSON"}, mimeTypes: ['application/json'], inputs: ['http'], outputs: ['analysis']
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
