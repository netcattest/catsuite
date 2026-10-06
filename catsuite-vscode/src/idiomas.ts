import * as vscode from 'vscode';
import { Idioma } from './nucleo/contratos';
import { textosPt, textosEn } from './nucleo/textos';
export { textosPt, textosEn } from './nucleo/textos';
export function idiomaAtual(): Idioma { const escolha = vscode.workspace.getConfiguration('catsuite').get<string>('idioma', 'sistema'); return escolha === 'pt-BR' || escolha === 'en' ? escolha : vscode.env.language.toLowerCase().startsWith('pt') ? 'pt-BR' : 'en'; }
export function traduzir(chave: string, argumentos: Record<string, string | number> = {}, idioma: Idioma = idiomaAtual()): string { const base = (idioma === 'pt-BR' ? textosPt as Record<string, string> : textosEn)[chave] ?? (idioma === 'pt-BR' ? textosPt.falhaGenerica : textosEn.falhaGenerica)!; return base.replace(/\{([^}]+)\}/g, (_, nome: string) => String(argumentos[nome] ?? '')); }
export function rotulos(): Record<string, string> { return idiomaAtual() === 'pt-BR' ? textosPt : textosEn; }
