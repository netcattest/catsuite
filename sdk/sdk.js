'use strict';
const __cat = {handlers:{}, request:[], response:[], commands:{}, steps:{}, parsers:{}, outbox:[], pending:{}, next:0, hook:false, result:null};
const __catCopy = value => JSON.parse(JSON.stringify(value));
function __catEmit(type, data) {
  if (__cat.hook) throw new Error('E_HOOK_ASYNC');
  if (__cat.outbox.length >= 128) throw new Error('E_QUEUE');
  if(JSON.stringify(data).length>128*1024)throw new Error('E_SIZE');
  __cat.outbox.push({type, data:__catCopy(data)});
}
function __catCall(type, data) {
  if (__cat.hook) throw new Error('E_HOOK_ASYNC');
  const id = String(++__cat.next);
  return new Promise((resolve, reject) => {
    __cat.pending[id] = {resolve,reject};
    try { __catEmit(type, {...data,callId:id}); }
    catch(error) { delete __cat.pending[id];reject(error); }
  });
}
function __catText(value) {
  if (!value || typeof value['pt-BR'] !== 'string' || typeof value.en !== 'string') throw new Error('E_TRANSLATION');
  return value;
}
const cat = Object.freeze({
  apiVersion:1, sdkVersion:"1.4.0",
  pipeline:{registerStep(options,handler) {
    __catText(options.title);
    if(!/^[a-z][a-z0-9_.-]{1,79}$/.test(options.id) || __cat.steps[options.id] || typeof handler!=="function" || !Array.isArray(options.inputs) || !Array.isArray(options.outputs))throw new Error("E_STEP");
    __cat.steps[options.id]={options:__catCopy(options),handler};
    __catEmit("step.register",options);
  }},
  parsers:{register(options,handler) {
    __catText(options.title);
    if(__cat.parsers[options.id] || typeof handler!=="function")throw new Error("E_PARSER");
    __cat.parsers[options.id]={options:__catCopy(options),handler};
    __catEmit("parser.register",options);
  }},
  connectors:{capabilities(connector) { return __catCall("connector.capabilities",{connector}); },run(options) { return __catCall("connector.run",options); },cancel(id) { __catEmit("connector.cancel",{id}); }},
  events:{on(name, fn) {
    if (!['http.request','http.response','http.complete'].includes(name) || typeof fn !== 'function') throw new Error('E_EVENT');
    (__cat.handlers[name] ||= []).push(fn);
  }},
  proxy:{onRequest(fn) { if(typeof fn!=='function')throw new Error('E_EVENT');__cat.request.push(fn); }, onResponse(fn) { if(typeof fn!=='function')throw new Error('E_EVENT');__cat.response.push(fn); }},
  http:{
    parseUrl(value) {
      const match=/^(https?):\/\/([^/?#]+)([^?#]*)(?:\?([^#]*))?$/.exec(value);
      if(!match || match[2].includes('@') || /[\s\\]/.test(value))throw new Error('E_HTTP');
      const authority=/^(?:\[([0-9a-fA-F:]+)\]|([^:]+))(?::([0-9]+))?$/.exec(match[2]);
      if(!authority)throw new Error('E_HTTP');
      const port=Number(authority[3] || (match[1]==='https'?443:80));
      if(!Number.isInteger(port) || port<1 || port>65535)throw new Error('E_HTTP');
      return {scheme:match[1],hostname:authority[1] || authority[2],port,pathname:match[3] || '/',query:match[4] || ''};
    },
    send(request) { return __catCall('http.send',{request}); },
    cancel(id) { __catEmit('http.cancel',{id}); }
  },
  external:{call(options) { return __catCall('external.call',options); }},
  laboratory:{capture(request) { return __catCall('laboratory.capture',{request}); }},
  tools:{repeater:{open(request) { __catEmit('repeater.open',{request}); }}},
  ui:{
    menu:{register(options) { __catText(options.title); __catEmit('menu.register',options); }},
    tab:{register(options) { __catText(options.title); __catEmit('tab.register',options); }},
    update(id, components) { __catEmit('ui.update',{id,components}); }
  },
  storage:{
    get(key) { return __catCall('storage.get',{key}); },
    async set(key,value) { await __catCall('storage.set',{key,value}); __catContext.storage[key]=__catCopy(value); },
    async delete(key) { await __catCall('storage.delete',{key}); delete __catContext.storage[key]; }
  },
  settings:{get(key) { return __catCopy(__catContext.settings[key] ?? null); }},
  resources:{get(path,mode='text') { return __catCall('resource.get',{path,mode}); }},
  findings:{add(finding) {
    __catText(finding.title); __catText(finding.description);
    return __catCall('finding.add',{finding});
  }},
  commands:{
    register(id, title, handler) {
      __catText(title);
      if (!/^[a-z][a-z0-9_.-]{1,79}$/.test(id) || typeof handler !== 'function' || __cat.commands[id]) throw new Error('E_COMMAND');
      __cat.commands[id]=handler;
      __catEmit('command.register',{id,title});
    },
    execute(id,args={}) { return __catCall('command.execute',{id,args}); }
  },
  i18n:{get locale() { return __catContext.locale; }, text(value) { __catText(value); return value[__catContext.locale === 'en' ? 'en' : 'pt-BR']; }},
  bytes:{
    fromText(text) {
      const s=unescape(encodeURIComponent(text));
      return Array.from(s, c=>c.charCodeAt(0));
    },
    toText(bytes) { return decodeURIComponent(escape(String.fromCharCode(...bytes))); }
  },
  log(message,level='info') { if(message && typeof message==='object') { __catText(message);__catEmit('log',{message:cat.i18n.text(message),text:message,level}); } else __catEmit('log',{message:String(message).slice(0,2048),level}); }
});
function __catDispatch(input) {
  __cat.result=null;
  if (input.kind === 'resolve') {
    const pending=__cat.pending[input.callId];
    if (pending) {
      delete __cat.pending[input.callId];
      input.error ? pending.reject(Object.assign(new Error(input.error),{code:input.error})) : pending.resolve(input.value);
    }
  } else if (input.kind === 'transform') {
    __cat.hook=true;
    try {
      let message=__catCopy(input.message);
      for (const fn of __cat[input.stage]) {
        const result=fn(__catCopy(message));
        if (result && typeof result.then === 'function') throw new Error('E_HOOK_ASYNC');
        if (result !== undefined && result !== null) message=result;
      }
      __cat.result=message;
    } finally { __cat.hook=false; }
  } else if (input.kind === 'event') {
    for (const fn of __cat.handlers[input.name] || []) {
      Promise.resolve().then(()=>fn(__catCopy(input.message))).catch(error=>__catEmit('log',{message:String(error),level:'error'}));
    }
  } else if (input.kind === 'command') {
    const fn=__cat.commands[input.id];
    if (!fn) throw new Error('E_COMMAND');
    Promise.resolve().then(()=>fn(input.args || {})).then(
      value=>__catEmit('job.complete',{jobId:input.jobId,value:value ?? null}),
      error=>__catEmit('job.error',{jobId:input.jobId,error:String(error)}));
   } else if (input.kind === 'step' || input.kind === 'parser') {
    const registered=(input.kind==='step'?__cat.steps:__cat.parsers)[input.id];
    if(!registered)throw new Error('E_STEP');
    __cat.next=input.checkpoint?.sequence || 0;
    const ctx=Object.freeze({revisionId:input.revisionId,protection:input.protection || 'PUBLIC',restored:__catCopy(input.checkpoint?.state ?? null),
      checkpoint(state) {
        const serial=JSON.stringify(state);
        if(serial===undefined || cat.bytes.fromText(serial).length>32768)throw new Error('E_CHECKPOINT');
        return __catCall('step.checkpoint',{jobId:input.jobId,state:JSON.parse(serial),sequence:__cat.next+1});
      },inputs:__catCopy(input.inputs || []),config:__catCopy(input.config || {}),runId:input.runId,nodeId:input.nodeId,
      emit(kind,data) { __catEmit('artifact.emit',{jobId:input.jobId,kind,data}); },
      progress(value) { if(typeof value!=='number' || value<0 || value>1)throw new Error('E_STEP');__catEmit('step.progress',{jobId:input.jobId,value}); },
      signal:Object.freeze({get aborted() { return !!__catContext.cancelled; }})});
    Promise.resolve().then(()=>registered.handler(ctx)).then(
      ()=>__catEmit('step.complete',{jobId:input.jobId}),
      error=>__catEmit('step.error',{jobId:input.jobId,error: error.code || String(error)}));
  } else if (input.kind === 'cancel') { __catContext.cancelled=true;
  } else if (input.kind === 'locale') { __catContext.locale=input.locale; }
}
function __catDrain() {
  const output={actions:__cat.outbox,result:__cat.result,hooks:{request:__cat.request.length,response:__cat.response.length,events:Object.keys(__cat.handlers).length},steps:Object.values(__cat.steps).map(v=>v.options),parsers:Object.values(__cat.parsers).map(v=>v.options)};
  __cat.outbox=[]; __cat.result=null;
  return output;
}
