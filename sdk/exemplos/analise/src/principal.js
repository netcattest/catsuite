cat.events.on('http.complete', async mensagem => {
  if (!mensagem.status || mensagem.headers.some(header => header.name.toLowerCase() === 'cache-control')) return;
  await cat.findings.add({
    fingerprint: 'cache:' + mensagem.url,
    title: { 'pt-BR': 'Cache-Control ausente', en: 'Missing Cache-Control' },
    description: { 'pt-BR': 'A resposta observada não declarou Cache-Control.', en: 'The observed response did not declare Cache-Control.' },
    severity: 'info', confidence: 'observed', url: mensagem.url,
    evidence: { response: mensagem }
  });
});
