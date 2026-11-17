import { Body, Controller, Get, HttpCode, Param, Post, Query, UseGuards } from '@nestjs/common';
import { z } from 'zod';
import { Feature, Me, Perm, Principal, RolesGuard } from '../auth/auth';
import { parse } from '../common/zod';
import { IamService, IdentitySchema } from './iam.service';

const Bulk = z.object({ identities: z.array(IdentitySchema).min(1).max(1000) }).strict();

/** IAM hygiene: identity inventory, privileged/inactive/excessive detection, change history, least-privilege proposals (never applied here). */
@Controller('api/v1/iam')
@UseGuards(RolesGuard)
@Feature('iam')
export class IamController {
  constructor(private s: IamService) {}

  @Get('identities') @Perm('identities:read')
  list(@Me() me: Principal, @Query() q: Record<string, string>) { return this.s.list(me.orgId, q); }

  @Post('identities') @HttpCode(201) @Perm('identities:write')
  async add(@Me() me: Principal, @Body() b: unknown) { return (await this.s.upsert(me, parse(IdentitySchema, b))).identity; }

  @Post('identities/bulk') @HttpCode(200) @Perm('identities:write')
  async bulk(@Me() me: Principal, @Body() b: unknown) {
    let created = 0, updated = 0, changes = 0;
    for (const i of parse(Bulk, b).identities) { const r = await this.s.upsert(me, i); if (r.created) created++; else updated++; changes += r.changes; }
    return { created, updated, changes };
  }

  @Get('identities/:id') @Perm('identities:read')
  detail(@Me() me: Principal, @Param('id') id: string) { return this.s.detail(me.orgId, id); }

  @Post('identities/:id/propose-reduction') @HttpCode(200) @Perm('identities:write')
  propose(@Me() me: Principal, @Param('id') id: string) { return this.s.proposeReduction(me, id); }

  @Get('risks') @Perm('identities:read')
  risks(@Me() me: Principal, @Query('inactiveDays') d?: string) { return this.s.risks(me.orgId, d ? Math.min(Math.max(Number(d) || 90, 1), 3650) : undefined); }

  @Get('summary') @Perm('identities:read')
  summary(@Me() me: Principal) { return this.s.summary(me.orgId); }

  @Get('changes') @Perm('identities:read')
  changes(@Me() me: Principal, @Query('identityId') id?: string) { return this.s.changes(me.orgId, id); }
}
