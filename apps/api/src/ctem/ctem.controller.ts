import { Body, Controller, Get, HttpCode, Param, Post, Query, UseGuards } from '@nestjs/common';
import { z } from 'zod';
import { Feature, Me, Perm, Principal, RolesGuard } from '../auth/auth';
import { parse } from '../common/zod';
import { AssetSchema, CtemService, RelationSchema, ScanResultSchema, VulnSchema } from './ctem.service';

const Verify = z.object({ method: z.enum(['dns_txt', 'manual_attestation']), note: z.string().max(500).optional() }).strict();
const Scope = z.object({ inScope: z.boolean() }).strict();
const Status = z.object({ status: z.enum(['open', 'in_progress', 'mitigated', 'resolved', 'accepted']), note: z.string().max(1000).optional(), owner: z.string().max(200).optional(), dueDate: z.string().regex(/^\d{4}-\d{2}-\d{2}/).optional() }).strict();
const Intel = z.object({ kind: z.enum(['nvd', 'kev', 'epss']), payload: z.unknown().refine((v) => v !== undefined && v !== null, 'payload is required') }).strict();
const Bulk = z.object({ assets: z.array(AssetSchema).min(1).max(500) }).strict();
const Tls = z.object({ port: z.number().int().min(1).max(65535).default(443) }).strict();
const Stale = z.object({ days: z.number().int().min(1).max(3650).default(30) }).strict();

/** CTEM: asset discovery & inventory, vulnerability management, attack surface, attack paths, contextual prioritisation. */
@Controller('api/v1')
@UseGuards(RolesGuard)
export class CtemController {
  constructor(private s: CtemService) {}

  // ── inventory (all plans) ──
  @Get('inventory/assets') @Perm('assets:read') @Feature('discovery')
  assets(@Me() me: Principal, @Query() q: Record<string, string>) { return this.s.listAssets(me.orgId, q); }

  @Post('inventory/assets') @HttpCode(201) @Perm('assets:write') @Feature('discovery')
  async addAsset(@Me() me: Principal, @Body() b: unknown) { return (await this.s.upsertAsset(me, parse(AssetSchema, b))).asset; }

  @Post('inventory/assets/bulk') @HttpCode(201) @Perm('assets:write') @Feature('discovery')
  async bulk(@Me() me: Principal, @Body() b: unknown) {
    let created = 0, updated = 0;
    for (const a of parse(Bulk, b).assets) { const r = await this.s.upsertAsset(me, a); if (r.created) created++; else updated++; }
    return { created, updated };
  }

  @Get('inventory/assets/:id') @Perm('assets:read') @Feature('discovery')
  asset(@Me() me: Principal, @Param('id') id: string) { return this.s.assetDetail(me.orgId, id); }

  @Post('inventory/assets/:id/ownership/challenge') @HttpCode(201) @Perm('assets:verify') @Feature('discovery')
  challenge(@Me() me: Principal, @Param('id') id: string) { return this.s.ownershipChallenge(me, id); }

  @Post('inventory/assets/:id/ownership/verify') @HttpCode(200) @Perm('assets:verify') @Feature('discovery')
  verify(@Me() me: Principal, @Param('id') id: string, @Body() b: unknown) { const x = parse(Verify, b); return this.s.verifyOwnership(me, id, x.method, x.note); }

  @Post('inventory/assets/:id/scope') @HttpCode(200) @Perm('assets:verify') @Feature('discovery')
  scope(@Me() me: Principal, @Param('id') id: string, @Body() b: unknown) { return this.s.setScope(me, id, parse(Scope, b).inScope); }

  @Post('inventory/assets/stale-check') @HttpCode(200) @Perm('assets:write') @Feature('ctem_advanced')
  stale(@Me() me: Principal, @Body() b: unknown) { return this.s.markStale(me, parse(Stale, b ?? {}).days); }

  @Post('inventory/relations') @HttpCode(201) @Perm('assets:write') @Feature('discovery')
  relate(@Me() me: Principal, @Body() b: unknown) { return this.s.relate(me, parse(RelationSchema, b)); }

  // ── vulnerabilities (all plans) ──
  @Get('vulns') @Perm('vulns:read') @Feature('vulns')
  vulns(@Me() me: Principal, @Query() q: Record<string, string>) { return this.s.listVulns(me.orgId, q); }

  @Post('vulns') @HttpCode(201) @Perm('vulns:write') @Feature('vulns')
  createVuln(@Me() me: Principal, @Body() b: unknown) { return this.s.createVuln(me, parse(VulnSchema, b)); }

  @Post('vulns/:id/status') @HttpCode(200) @Perm('vulns:write') @Feature('vulns')
  status(@Me() me: Principal, @Param('id') id: string, @Body() b: unknown) { const x = parse(Status, b); return this.s.setVulnStatus(me, id, x.status, x.note, x.owner, x.dueDate); }

  @Post('vulns/import-findings') @HttpCode(200) @Perm('vulns:write') @Feature('vulns')
  fromFindings(@Me() me: Principal) { return this.s.importFromFindings(me); }

  @Post('intel/import') @HttpCode(200) @Perm('intel:write') @Feature('vulns')
  intel(@Me() me: Principal, @Body() b: unknown) { const x = parse(Intel, b); return this.s.importIntel(me, x.kind, x.payload); }

  @Get('ctem/priorities') @Perm('vulns:read') @Feature('vulns')
  priorities(@Me() me: Principal) { return this.s.priorities(me.orgId); }

  @Post('ctem/reprioritize') @HttpCode(200) @Perm('vulns:write') @Feature('vulns')
  reprio(@Me() me: Principal) { return this.s.reprioritize(me.orgId, true); }

  // ── attack surface & paths (business and above) ──
  @Get('exposures/findings') @Perm('exposures:read') @Feature('ctem_advanced')
  exposures(@Me() me: Principal, @Query() q: Record<string, string>) { return this.s.listExposures(me.orgId, q); }

  @Post('exposures/observe') @HttpCode(200) @Perm('exposures:write') @Feature('ctem_advanced')
  observe(@Me() me: Principal, @Body() b: unknown) { return this.s.observe(me, parse(ScanResultSchema, b)); }

  @Post('inventory/assets/:id/tls-check') @HttpCode(200) @Perm('exposures:write') @Feature('ctem_advanced')
  tls(@Me() me: Principal, @Param('id') id: string, @Body() b: unknown) { return this.s.tlsCheck(me, id, parse(Tls, b ?? {}).port); }

  @Get('exposures/history') @Perm('exposures:read') @Feature('ctem_advanced')
  history(@Me() me: Principal, @Query('assetId') assetId?: string) { return this.s.history(me.orgId, assetId); }

  @Get('ctem/attack-paths') @Perm('paths:read') @Feature('ctem_advanced')
  paths(@Me() me: Principal, @Query('maxDepth') d?: string, @Query('limit') l?: string, @Query('target') target?: string) {
    return this.s.attackPaths(me.orgId, { maxDepth: Math.min(Number(d) || 6, 8), maxPaths: Math.min(Number(l) || 25, 100), ...(target ? { targets: target.split(',') } : {}) });
  }
}
