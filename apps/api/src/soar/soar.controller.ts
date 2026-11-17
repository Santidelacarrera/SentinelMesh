import { Body, Controller, Get, HttpCode, Param, Post, Query, UseGuards } from '@nestjs/common';
import { z } from 'zod';
import { Feature, Me, Perm, Principal, RolesGuard } from '../auth/auth';
import { parse } from '../common/zod';
import { AutomationSchema, PlaybookSchema, PlaybooksService } from './playbooks.service';
import { ChannelSchema, NotificationsService } from '../notifications/notifications.service';

const State = z.object({ enabled: z.boolean() }).strict();
const Kill = z.object({ on: z.boolean(), reason: z.string().min(5).max(500) }).strict();
const Trig = z.object({ type: z.enum(['signal', 'finding', 'vulnerability', 'exposure', 'identity']), entityId: z.string().min(1).max(100) }).strict();
const Stop = z.object({ reason: z.string().min(5).max(500) }).strict();
const Patch = z.object({ enabled: z.boolean().optional(), mutedUntil: z.string().datetime().nullable().optional(), minSeverity: z.enum(['critical', 'high', 'medium', 'low', 'info']).optional(), events: z.array(z.string().max(60)).max(50).optional() }).strict();

/** SOAR: playbooks, automation levels (OBSERVE / ASSISTED / AUTOMATED), human approval, kill switch, run history. */
@Controller('api/v1/soar')
@UseGuards(RolesGuard)
@Feature('soar')
export class SoarController {
  constructor(private s: PlaybooksService) {}

  @Get('playbooks') @Perm('playbooks:read')
  list(@Me() me: Principal) { return this.s.list(me.orgId); }

  @Post('playbooks') @HttpCode(201) @Perm('playbooks:write')
  publish(@Me() me: Principal, @Body() b: unknown) { return this.s.publish(me, parse(PlaybookSchema, b)); }

  @Post('playbooks/install-defaults') @HttpCode(200) @Perm('playbooks:write')
  defaults(@Me() me: Principal) { return this.s.installDefaults(me); }

  @Get('playbooks/:key/versions') @Perm('playbooks:read')
  versions(@Me() me: Principal, @Param('key') key: string) { return this.s.versions(me.orgId, key); }

  @Post('playbooks/:key/state') @HttpCode(200) @Perm('playbooks:enable')
  state(@Me() me: Principal, @Param('key') key: string, @Body() b: unknown) { return this.s.setEnabled(me, key, parse(State, b).enabled); }

  @Get('automation') @Perm('runs:read')
  automation(@Me() me: Principal) { return this.s.automation(me.orgId); }

  @Post('automation') @HttpCode(200) @Perm('automation:manage')
  setAutomation(@Me() me: Principal, @Body() b: unknown) { return this.s.setAutomation(me, parse(AutomationSchema, b)); }

  @Post('kill-switch') @HttpCode(200) @Perm('runs:approve')
  kill(@Me() me: Principal, @Body() b: unknown) { const x = parse(Kill, b); return this.s.killSwitch(me, x.on, x.reason); }

  @Get('runs') @Perm('runs:read')
  runs(@Me() me: Principal, @Query() q: Record<string, string>) { return this.s.runs(me.orgId, q); }

  @Get('runs/:id') @Perm('runs:read')
  run(@Me() me: Principal, @Param('id') id: string) { return this.s.run(me.orgId, id); }

  @Post('runs/:id/stop') @HttpCode(200) @Perm('runs:approve')
  stop(@Me() me: Principal, @Param('id') id: string, @Body() b: unknown) { return this.s.stop(me, id, parse(Stop, b).reason); }

  @Get('approvals') @Perm('approvals:read')
  approvals(@Me() me: Principal) { return this.s.pendingApprovals(me.orgId); }

  @Post('trigger') @HttpCode(200) @Perm('runs:trigger')
  trigger(@Me() me: Principal, @Body() b: unknown) { const x = parse(Trig, b); return this.s.trigger(me, x.type, x.entityId); }

  @Post('identity-scan') @HttpCode(200) @Perm('runs:trigger')
  identityScan(@Me() me: Principal) { return this.s.scanIdentities(me); }
}

/** Notification channels (email, Slack, Microsoft Teams). Available from the Business plan. */
@Controller('api/v1/notifications')
@UseGuards(RolesGuard)
@Feature('notifications')
export class NotificationsController {
  constructor(private n: NotificationsService) {}

  @Get('channels') @Perm('channels:read')
  list(@Me() me: Principal) { return this.n.list(me.orgId); }

  @Post('channels') @HttpCode(201) @Perm('channels:manage')
  create(@Me() me: Principal, @Body() b: unknown) { return this.n.create(me, parse(ChannelSchema, b)); }

  @Post('channels/:id') @HttpCode(200) @Perm('channels:manage')
  patch(@Me() me: Principal, @Param('id') id: string, @Body() b: unknown) { return this.n.patch(me, id, parse(Patch, b)); }

  @Post('channels/:id/test') @HttpCode(200) @Perm('channels:manage')
  test(@Me() me: Principal, @Param('id') id: string) { return this.n.test(me, id); }

  @Get('log') @Perm('channels:read')
  log(@Me() me: Principal, @Query() q: { channelId?: string; status?: string }) { return this.n.logs(me.orgId, q); }
}
