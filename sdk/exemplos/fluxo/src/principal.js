cat.pipeline.registerStep({
  id: 'fluxo.inspecionar', title: {"pt-BR":"Etapa de fluxo","en":"Etapa de fluxo"}, inputs: ['http'], outputs: ['http', 'analysis']
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
