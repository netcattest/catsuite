type CatProtection="PUBLIC"|"PROTECTED"|"SECRET";
type CatText = {"pt-BR": string; en: string};
type CatHeader = {name: string; value: string};
type CatBody = {bytes: number[]; size?: number; complete: boolean; truncated: boolean; available: boolean; mutable: boolean; representation?:"wire"|"decoded"; sha256?: string; reference?: string};
type CatMessage = {id: string; source: string; session: string|null; stage: "request"|"response"; url: string; method: string; headers: CatHeader[]; body: CatBody; status?: number; reason?: string; time: number; request?: CatMessage; pluginOrigin?: string; extensionTrail?: object[]};
type CatRequest = {id?: string; url: string; method?: string; headers?: CatHeader[]; body?: {bytes: number[]}};
type CatComponent =
  | {type:"text"; text:CatText}
  | {type:"button"; label:CatText; command:string; args?:object}
  | {type:"field"|"filter"; id:string; label:CatText; value?:string}
  | {type:"list"; items:CatText[]}
  | {type:"table"; columns:CatText[]; rows:(string|number|boolean)[][]}
  | {type:"http"; message:CatMessage}
  | {type:"progress"; value?:number}
  | {type:"json";label?:CatText;value:unknown}
  | {type:"diff";label?:CatText;before:string;after:string}
  | {type:"timeline";label?:CatText;items:{title:CatText;detail?:string;time?:number}[]}
  | {type:"chart";label?:CatText;values:{label:CatText|string;value:number}[]}
  | {type:"graph";label?:CatText;nodes:{id:string;label:CatText|string;x?:number;y?:number}[];edges:{from:string;to:string}[]};
type CatFinding = {
  fingerprint?:string; title:CatText; description:CatText;
  severity:"info"|"low"|"medium"|"high"|"critical";
  confidence:"observed"|"confirmed"|"hypothesis";
  status?:"open"|"resolved"|"false_positive";
  url:string; evidence?:object;
};
declare const cat: {
  readonly apiVersion:1;
  readonly sdkVersion:"1.4.0";
  pipeline:{registerStep(options:CatStepDefinition,handler:(context:CatStepContext)=>void|Promise<void>):void};
  parsers:{register(options:CatStepDefinition & {mimeTypes:string[]},handler:(context:CatStepContext)=>void|Promise<void>):void};
  connectors:{capabilities(connectorId:string):Promise<CatCapabilityCatalog>;run(options:CatConnectorRun):Promise<CatConnectorResult>;cancel(id:string):void};
  events:{on(name:"http.request"|"http.response"|"http.complete",handler:(message:CatMessage)=>void|Promise<void>):void};
  proxy:{onRequest(handler:(message:CatMessage)=>CatMessage|void):void;onResponse(handler:(message:CatMessage)=>CatMessage|void):void};
  http:{
    send(request:CatRequest):Promise<CatMessage>;
    cancel(id:string):void;
    parseUrl(url:string):{scheme:string;hostname:string;port:number;pathname:string;query:string};
  };
  laboratory:{capture(request:CatRequest):Promise<CatMessage>};
  external:{call(options:CatRequest & {credentialId?:string}):Promise<CatMessage>};
  tools:{repeater:{open(request:CatRequest):void}};
  ui:{
    menu:{register(options:{id:string;title:CatText;command:string;contexts?:("request"|"response")[]}):void};
    tab:{register(options:{id:string;title:CatText;components:CatComponent[]}):void};
    update(id:string,components:CatComponent[]):void;
  };
  storage:{get<T=unknown>(key:string):Promise<T|null>;set(key:string,value:unknown):Promise<void>;delete(key:string):Promise<void>};
  settings:{get<T=unknown>(key:string):T|null};
  resources:{get(path:string,mode?:"text"):Promise<string>;get(path:string,mode:"bytes"):Promise<number[]>};
  findings:{add(finding:CatFinding):Promise<string>};
  commands:{register(id:string,title:CatText,handler:(args:Record<string,unknown>)=>unknown|Promise<unknown>):void;execute(id:string,args?:object):Promise<string>};
  i18n:{readonly locale:"pt-BR"|"en";text(value:CatText):string};
  bytes:{fromText(text:string):number[];toText(bytes:number[]):string};
  log(message:string|CatText,level?:"info"|"warning"|"error"):void;
};
type CatArtifactKind="http"|"endpoint"|"jwt"|"secret"|"analysis"|"finding"|"record"|"javascript"|"openapi";
type CatArtifact={readonly id:string;readonly kind:CatArtifactKind;readonly schemaVersion:1;readonly data:unknown;readonly sha256:string;readonly run:string;readonly node:string;readonly time:number;readonly sources:string[];readonly protected:boolean;readonly protection:CatProtection;readonly revisionId:string;readonly module:{id:string;version:string;sha256?:string}};
type CatStepDefinition={id:string;title:CatText;inputs:CatArtifactKind[];outputs:CatArtifactKind[]};
type CatStepContext={readonly inputs:CatArtifact[];readonly config:Record<string,unknown>;readonly runId:string;readonly nodeId:string;readonly revisionId:string;readonly protection:CatProtection;readonly restored:unknown;checkpoint(state:unknown):Promise<boolean>;emit(kind:CatArtifactKind,data:unknown):void;progress(value:number):void;readonly signal:{readonly aborted:boolean}};

type CatSettingsField={title:CatText;type:"string"|"boolean"|"integer"|"number"|"credential"|"secret";enum?:unknown[];minimum?:number;maximum?:number};
type CatWorkflowNode={id:string;kind:"capture"|"filter"|"condition"|"join"|"parser"|"request"|"crawler"|"storage"|"report"|"connector"|"extension";inputs:CatArtifactKind[];outputs:CatArtifactKind[];extension?:string;step?:string;config:Record<string,unknown>;x?:number;y?:number};
type CatWorkflow={format:"catflow";formatVersion:2|3|4|5;protection:CatProtection;id:string;revisionId?:string;lineageId?:string;parentRevision?:string;name:CatText;trigger:"manual"|"capture";network:boolean;laboratory:boolean;targets:string[];methods:string[];connectors:string[];nodes:CatWorkflowNode[];edges:{from:string;to:string;when?:"true"|"false"}[]};

type CatCapabilityId="nuclei.scan"|"http.probe"|"web.crawl"|"api.schema.test"|"assets.subdomains.discover"|"dns.resolve"|"dns.enumerate"|"dns.permute"|"urls.history"|"assets.search"|"net.ports.discover"|"net.services.fingerprint"|"web.paths.fuzz"|"http.parameters.fuzz"|"web.vhosts.fuzz"|"http.parameters.discover"|"web.xss.analyze"|"api.sqli.validate"|"jwt.analyze"|"tls.assess"|"web.server.assess"|"code.secrets.scan"|"code.sast.scan";
type CatExecutor={id:string;version:string;image:string;binarySha256:string};
type CatCapability={id:string;area:string;stage:number;title:CatText;engines:string[];inputs:CatArtifactKind[];outputs:CatArtifactKind[];state:"available"|"not-installed"|"incompatible"|"not-authorized"|"unavailable"|"planned";contractVersion:1|2;parametersSchema?:object;executor?:CatExecutor;executors?:Record<string,CatExecutor>;limits?:Record<string,number>};
type CatCapabilityCatalog={protocol:2;catalogVersion:1;catalog:CatCapability[];broker?:CatExecutor};
type CatCapabilityParameters={profile:"read-only"|"mutation-approved"|"external-approved"|"active-approved";methods:string[];requests:number;depth?:number;pages?:number;examples?:number;seed?:number;operations?:string[];paths?:string[];maxResults?:number;providers?:string[];recordTypes?:("A"|"AAAA"|"CNAME"|"MX"|"NS"|"TXT")[];patterns?:("prefix"|"suffix"|"environment")[];ports?:number[];parameter?:string;virtualHosts?:string[]};
type CatConnectorRun={connector:string;capability?:CatCapabilityId;tool?:CatToolId;id?:string;targets:string[];templateIds?:string[];headers?:CatHeader[];parameters?:CatCapabilityParameters;schemaId?:string;schemaHash?:string;resourceId?:string;resourceHash?:string;resourceKind?:"wordlist"|"snapshot"|"jwt";baseUrl?:string};
type CatConnectorResult={id:string;capability:CatCapabilityId;status:string;flow:string;revision:string;node:string;protection:CatProtection;results:object[];receipts?:object[];binary:object;batches:object[];requestsReserved?:number};

type CatToolId="nuclei"|"httpx"|"katana"|"schemathesis"|"subfinder"|"amass"|"dnsx"|"alterx"|"uncover"|"gau"|"waybackurls"|"naabu"|"nmap"|"ffuf"|"arjun"|"dalfox"|"sqlmap"|"jwt_tool"|"testssl"|"nikto"|"gitleaks"|"trufflehog"|"semgrep";
