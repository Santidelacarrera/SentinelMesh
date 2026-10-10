import type { Severity } from '../types';

const rtf = new Intl.RelativeTimeFormat('es', { numeric: 'auto' });
export function ago(iso: string, now = Date.now()): string {
  const s = Math.round((new Date(iso).getTime() - now) / 1000), a = Math.abs(s);
  if (a < 45) return 'ahora mismo';
  if (a < 3600) return rtf.format(Math.round(s / 60), 'minute');
  if (a < 86400) return rtf.format(Math.round(s / 3600), 'hour');
  return rtf.format(Math.round(s / 86400), 'day');
}
export const clock = (iso: string) => new Date(iso).toLocaleString('es', { dateStyle: 'medium', timeStyle: 'medium' });
export const short = (h: string, n = 10) => (h.length > n ? `${h.slice(0, n)}…` : h);

export const SEV_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
export const SEV_LABEL: Record<Severity, string> = { critical: 'Crítica', high: 'Alta', medium: 'Media', low: 'Baja', info: 'Informativa' };

export function plural(n: number, one: string, many: string) { return `${n} ${n === 1 ? one : many}`; }

export const WORKFLOW_LABEL: Record<string, string> = {
  'credential-rotation': 'Rotación de credencial', 'waf-remediation': 'Regla de WAF', 'iam-trim': 'Recorte de permisos IAM', 'incident-response': 'Respuesta a incidente',
};
export const STEP_LABEL: Record<string, string> = {
  'create-new-credential': 'Crear la nueva credencial', 'update-secret-store': 'Apuntar el gestor de secretos a la nueva', 'healthcheck-new-credential': 'Comprobar el servicio con la nueva',
  'revoke-old-credential': 'Revocar la credencial anterior', 'apply-waf-rule': 'Aplicar la regla en el WAF', 'apply-iam-policy': 'Sustituir la política del rol',
  'collect-forensics': 'Congelar la evidencia forense', 'summarize-evidence': 'Resumir citando la evidencia', 'isolate-service': 'Aislar el servicio', 'notify-secops': 'Avisar a SecOps',
};
export const stepLabel = (n: string) => STEP_LABEL[n] ?? n;
