import type { Plan } from '../types';

export interface Impact { headline: string; effects: string[]; reversible: boolean; reversal: string }

/** Plain-language consequences derived from the plan's real parameters — what the signer is actually agreeing to. */
export function describeImpact(p: Plan): Impact {
  const pa = p.params ?? {};
  switch (p.kind) {
    case 'isolation':
      return { headline: `Aislar «${p.targetRef}» de la red`, reversible: true,
        effects: [`Todas las instancias de ${p.targetRef} pasan a un grupo de cuarentena: sin tráfico saliente y con entrada solo desde el bastión forense.`, 'Los usuarios del servicio notarán la caída hasta que se restaure.'],
        reversal: 'Los grupos de seguridad anteriores quedan guardados en una etiqueta de cada instancia.' };
    case 'waf': {
      const r = (pa['rule'] ?? {}) as { name?: string; action?: string; addresses?: string[] };
      const n = r.addresses?.length ?? 0;
      return { headline: `${(r.action ?? 'block') === 'block' ? 'Bloquear' : 'Marcar'} ${n} ${n === 1 ? 'dirección' : 'direcciones'} en «${r.name ?? p.targetRef}»`, reversible: true,
        effects: [`Se crea o amplía el conjunto de IP y la regla «${r.name}» en ${p.targetRef}.`, ...(r.addresses ?? []).slice(0, 4).map((a) => `Origen afectado: ${a}`), 'Cualquier cliente legítimo detrás de esos rangos también quedaría bloqueado.'],
        reversal: 'Se revierte quitando las direcciones del conjunto de IP.' };
    }
    case 'iam': {
      const cur = (pa['current']?.statements ?? []).flatMap((s: any) => s.actions) as string[];
      const next = (pa['proposed']?.statements ?? []).flatMap((s: any) => s.actions) as string[];
      const removed = cur.filter((a) => !next.includes(a));
      return { headline: `Recortar «${p.targetRef}» a ${next.length} de ${cur.length} permisos`, reversible: true,
        effects: [`Se eliminan: ${removed.join(', ') || 'ninguno'}.`, pa['critical'] ? 'El rol está marcado como crítico.' : 'El rol no está marcado como crítico.',
          'Si algún proceso usa un permiso que no aparece en el periodo auditado, empezará a fallar.'],
        reversal: 'La política anterior queda en este plan y puede volver a aplicarse.' };
    }
    case 'rotation':
      return { headline: 'Revocar la versión anterior de la credencial', reversible: false,
        effects: ['La nueva versión ya está activa y el servicio respondió bien con ella.', 'Al firmar, la versión anterior deja de ser válida. No hay vuelta atrás.'],
        reversal: 'Irreversible: habría que emitir otra credencial.' };
    default:
      return { headline: p.targetRef, effects: [], reversible: false, reversal: '' };
  }
}
export const KIND_LABEL: Record<string, string> = { isolation: 'Aislamiento', waf: 'Regla de WAF', iam: 'Recorte de permisos', rotation: 'Revocación', terraform: 'Terraform' };
