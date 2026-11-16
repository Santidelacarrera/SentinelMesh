import { Body, Controller, Get, HttpCode, Param, Post, Query, UseGuards } from '@nestjs/common';
import { Feature, Me, Perm, Principal, RolesGuard } from '../auth/auth';
import { parse } from '../common/zod';
import { ConnectorSchema, ConnectorUpdateSchema, ConnectorsService } from './connectors.service';
import { SignalSchema, SignalsService } from '../signals/signals.service';
import { z } from 'zod';

const SignalBatch = z.object({ signals: z.array(SignalSchema).min(1).max(500) }).strict();

@Controller('api/v1')
@UseGuards(RolesGuard)
export class ConnectorsController {
  constructor(private s: ConnectorsService, private signals: SignalsService) {}

  @Get('connectors/catalog') @Perm('connectors:read')
  catalog() { return this.s.catalog(); }

  @Get('connectors') @Perm('connectors:read') @Feature('connectors')
  list(@Me() me: Principal) { return this.s.list(me.orgId); }

  @Get('connectors/health') @Perm('connectors:read') @Feature('connectors')
  health(@Me() me: Principal) { return this.s.health(me.orgId); }

  @Post('connectors') @HttpCode(201) @Perm('connectors:manage') @Feature('connectors')
  create(@Me() me: Principal, @Body() b: unknown) { return this.s.create(me, parse(ConnectorSchema, b)); }

  @Get('connectors/:id') @Perm('connectors:read') @Feature('connectors')
  detail(@Me() me: Principal, @Param('id') id: string) { return this.s.detail(me.orgId, id); }

  @Post('connectors/:id') @HttpCode(200) @Perm('connectors:manage') @Feature('connectors')
  update(@Me() me: Principal, @Param('id') id: string, @Body() b: unknown) { return this.s.update(me, id, parse(ConnectorUpdateSchema, b)); }

  @Post('connectors/:id/enable') @HttpCode(200) @Perm('connectors:manage') @Feature('connectors')
  enable(@Me() me: Principal, @Param('id') id: string) { return this.s.setEnabled(me, id, true); }

  @Post('connectors/:id/disable') @HttpCode(200) @Perm('connectors:manage') @Feature('connectors')
  disable(@Me() me: Principal, @Param('id') id: string) { return this.s.setEnabled(me, id, false); }

  @Post('connectors/:id/test') @HttpCode(200) @Perm('connectors:manage') @Feature('connectors')
  test(@Me() me: Principal, @Param('id') id: string) { return this.s.test(me, id); }

  @Post('connectors/:id/sync') @HttpCode(200) @Perm('connectors:sync') @Feature('connectors')
  sync(@Me() me: Principal, @Param('id') id: string) { return this.s.sync(me, id); }

  // signals (events) from any source, including connectors and simulators
  @Get('signals') @Perm('signals:read')
  signalList(@Me() me: Principal, @Query() q: Record<string, string>) { return this.signals.list(me.orgId, q); }

  @Post('signals') @HttpCode(201) @Perm('signals:write')
  async ingest(@Me() me: Principal, @Body() b: unknown) { const r = await this.signals.ingest(me.orgId, me.userId, parse(SignalBatch, b).signals); return { created: r.created, duplicates: r.duplicates }; }
}
