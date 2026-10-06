const titulo = {"pt-BR":"Painel e comandos","en":"Painel e comandos"};
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
