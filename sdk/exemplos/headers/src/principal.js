cat.proxy.onRequest(mensagem => {
  if (!['GET', 'HEAD'].includes(mensagem.method)) return mensagem;
  mensagem.headers = mensagem.headers.filter(header => header.name.toLowerCase() !== 'x-cat-lab');
  mensagem.headers.push({ name: 'X-Cat-Lab', value: 'studio' });
  return mensagem;
});
