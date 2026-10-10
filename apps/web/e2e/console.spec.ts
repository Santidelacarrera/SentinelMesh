import { expect, Page, test } from '@playwright/test';

const login = async (page: Page, key: string) => {
  await page.goto('/'); await page.getByLabel('Clave de acceso').fill(key); await page.getByRole('button', { name: 'Entrar' }).click();
  await expect(page.getByRole('navigation', { name: 'Principal' })).toBeVisible();
};
const hold = async (page: Page, name: RegExp, ms = 1500) => {
  const b = page.getByRole('button', { name }); await b.scrollIntoViewIfNeeded(); const box = (await b.boundingBox())!;
  await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2); await page.mouse.down(); await page.waitForTimeout(ms); await page.mouse.up();
};

test('rejects a bad key with a clear message', async ({ page }) => {
  await page.goto('/'); await page.getByLabel('Clave de acceso').fill('nope'); await page.getByRole('button', { name: 'Entrar' }).click();
  await expect(page.getByRole('alert')).toContainText('no es válida');
});

test('overview explains the situation in a sentence and maps exposure', async ({ page }) => {
  await login(page, 'dev-viewer');
  await expect(page.locator('.lede')).toContainText('hallazgos abiertos');
  await expect(page.locator('.lede')).toContainText('esperan tu firma');
  await expect(page.getByRole('button', { name: /payments:/ })).toBeVisible();
  await page.screenshot({ path: 'shots/01-resumen.png', fullPage: true });
  await page.getByRole('button', { name: /payments:/ }).click();
  await expect(page).toHaveURL(/hallazgos\?asset=payments/);
});

test('finding detail shows the severity ledger and the report → plan trace', async ({ page }) => {
  await login(page, 'dev-analyst'); await page.goto('/#/hallazgos');
  await page.getByRole('link', { name: /XSS reflejado/ }).first().click();
  await expect(page.getByText('Por qué esta severidad')).toBeVisible();
  await expect(page.getByText('El activo está expuesto a Internet')).toBeVisible();
  await expect(page.getByText('sha256').first()).toBeVisible();
  await page.screenshot({ path: 'shots/02-hallazgo.png', fullPage: true });
});

test('a viewer cannot sign; a quick click never signs; a full hold does', async ({ page }) => {
  await login(page, 'dev-viewer'); await page.goto('/#/decisiones');
  await expect(page.getByText('Tu rol no puede firmar')).toBeVisible();
  await expect(page.getByRole('button', { name: /Mantén pulsado/ })).toBeDisabled();
  await page.getByRole('button', { name: 'Salir' }).click();

  await login(page, 'dev-approver'); await page.goto('/#/decisiones');
  await page.getByRole('button', { name: /Regla de WAF · payments-gateway/ }).click();
  await expect(page.getByRole('heading', { name: /Bloquear 2 direcciones/ })).toBeVisible();
  await expect(page.locator('.diff .add').first()).toBeVisible();
  await page.evaluate(() => window.scrollTo(0, 0)); await page.screenshot({ path: 'shots/03-decision-waf.png' });

  await hold(page, /Mantén pulsado/, 250);
  await expect(page.locator('.signed')).toHaveCount(0);

  await hold(page, /Mantén pulsado|Sigue/, 1600);
  await expect(page.locator('.signed')).toContainText('Firmada por u_approver');
  await page.screenshot({ path: 'shots/04-firmada.png', fullPage: true });

  await page.getByRole('button', { name: /Aislamiento · auth-api/ }).click();
  await page.getByRole('button', { name: 'Rechazar' }).click();
  await expect(page.getByRole('alert')).toContainText('Explica brevemente');
  await page.getByLabel('Comentario (obligatorio si rechazas)').fill('Prefiero limitar por rango primero.');
  await page.getByRole('button', { name: 'Rechazar' }).click();
  await expect(page.locator('.signed.rejected')).toContainText('Rechazada');
});

test('the pending badge, incidents, identities and audit chain work', async ({ page }) => {
  await login(page, 'dev-analyst');
  await expect(page.locator('.nav .count')).toBeVisible();
  await page.goto('/#/incidentes'); await expect(page.getByText('Integridad verificada')).toBeVisible();
  await page.getByRole('button', { name: 'ev-log-1' }).first().click(); await expect(page.locator('.ev.hl')).toBeVisible();
  await page.screenshot({ path: 'shots/05-incidente.png', fullPage: true });
  await page.goto('/#/identidades'); await page.getByRole('button', { name: 'Analizar', exact: true }).click();
  await expect(page.locator('.perm.unused').first()).toBeVisible();
  await page.screenshot({ path: 'shots/06-identidades.png', fullPage: true });
  await page.goto('/#/auditoria'); await expect(page.getByRole('status').filter({ hasText: 'Cadena' })).toContainText('Cadena íntegra');
  await page.goto('/#/ejecuciones'); await expect(page.locator('.steps').first()).toBeVisible();
  await page.screenshot({ path: 'shots/07-ejecuciones.png', fullPage: true });
});

test('is usable on a phone', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 800 }); await login(page, 'dev-approver'); await page.goto('/#/decisiones');
  expect(await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth + 1)).toBe(false);
  await page.screenshot({ path: 'shots/08-movil.png', fullPage: true });
});
