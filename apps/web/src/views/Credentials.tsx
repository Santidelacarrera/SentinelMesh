import { useState } from 'react';
import { go, useResource, useSession, useToast } from '../api';
import { Empty, ErrorBanner, Page, Skeleton } from '../ui/kit';
import type { Credential } from '../types';

const ST: Record<string, [string, string]> = { exposed: ['Expuesta', 'risk'], active: ['Activa', 'ok'], revoked: ['Revocada', ''] };

export function Credentials() {
  const res = useResource<Credential[]>('/credentials', 8000), { api, me } = useSession(), toast = useToast(), [busy, setBusy] = useState(''), [err, setErr] = useState('');
  const rotate = async (c: Credential) => { setBusy(c.id); setErr(''); try { await api.post('/secrets/rotate', { credentialId: c.id }); toast('Rotación iniciada. Revocar la anterior requerirá tu firma.'); go('/ejecuciones'); } catch (e) { setErr((e as Error).message); } finally { setBusy(''); } };
  return (
    <Page title="Credenciales" lede="Solo se guarda la forma enmascarada. La rotación no corta el servicio: la clave anterior sigue válida hasta que firmas su revocación.">
      {(res.error || err) && <ErrorBanner message={res.error ?? err} retry={res.reload} />}
      <section className="panel">{!res.data ? <Skeleton rows={4} /> : res.data.length === 0 ? <Empty title="Sin credenciales gestionadas">Cuando el escáner de secretos detecte una fuga, la credencial aparecerá aquí lista para rotar.</Empty> : (
        <table><thead><tr><th>Credencial</th><th>Servicio</th><th>Valor</th><th>Versión</th><th>Estado</th><th><span className="sr">Acción</span></th></tr></thead><tbody>
          {res.data.map((c) => <tr key={c.id}><td><b>{c.name}</b></td><td>{c.service}</td><td><code>{c.maskedValue}</code></td><td>v{c.currentVersion}</td><td><span className={`chip ${ST[c.status][1]}`}>{ST[c.status][0]}</span></td>
            <td><button className="btn" disabled={me.role === 'viewer' || busy === c.id} onClick={() => rotate(c)}>Rotar</button></td></tr>)}</tbody></table>)}</section>
    </Page>
  );
}
