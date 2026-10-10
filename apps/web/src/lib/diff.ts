export type DiffKind = 'add' | 'del' | 'ctx' | 'meta';
export interface DiffLine { kind: DiffKind; text: string; n?: number }

export function parseDiff(diff: string): DiffLine[] {
  let n = 0;
  return diff.split('\n').map((l) => {
    if (l.startsWith('---') || l.startsWith('+++')) return { kind: 'meta' as const, text: l };
    n++;
    if (l.startsWith('+')) return { kind: 'add' as const, text: l.slice(1).replace(/^ /, ''), n };
    if (l.startsWith('-')) return { kind: 'del' as const, text: l.slice(1).replace(/^ /, ''), n };
    return { kind: 'ctx' as const, text: l.replace(/^ {2}/, ''), n };
  });
}
export const diffStats = (lines: DiffLine[]) => ({ added: lines.filter((l) => l.kind === 'add').length, removed: lines.filter((l) => l.kind === 'del').length });
