import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import { Db } from '../store/db';
import type { Plan } from '../store/enterprise.models';
import { PLATFORM_ORG } from '../auth/rbac';

/**
 * Feature gating and usage limits per plan. The numbers are ILLUSTRATIVE placeholders for the licensing mechanism (see
 * docs/COMMERCIAL_MODEL.md): they are not market prices or contractual commitments.
 */
export type Feature = 'discovery' | 'vulns' | 'dashboard' | 'reports' | 'ctem_advanced' | 'iam' | 'connectors' | 'cases' | 'notifications' | 'ai' | 'soar' | 'sso' | 'advanced_audit' | 'custom_roles' | 'privacy_tools';
const STARTER: Feature[] = ['discovery', 'vulns', 'dashboard', 'reports'];
const BUSINESS: Feature[] = [...STARTER, 'ctem_advanced', 'iam', 'connectors', 'cases', 'notifications', 'ai'];
export const PLAN_FEATURES: Record<Plan, ReadonlySet<Feature>> = {
  starter: new Set(STARTER), business: new Set(BUSINESS), enterprise: new Set([...BUSINESS, 'soar', 'sso', 'advanced_audit', 'custom_roles', 'privacy_tools']),
};
export type LimitKey = 'assets' | 'users' | 'connectors' | 'eventsPerDay';
export const PLAN_LIMITS: Record<Plan, Record<LimitKey, number>> = {
  starter: { assets: 250, users: 5, connectors: 0, eventsPerDay: 10_000 },
  business: { assets: 5_000, users: 50, connectors: 5, eventsPerDay: 500_000 },
  enterprise: { assets: Infinity, users: Infinity, connectors: Infinity, eventsPerDay: Infinity },
};

@Injectable()
export class Entitlements {
  constructor(private db: Db) {}
  /** Self-hosted installs without an org profile get DEFAULT_PLAN (enterprise unless told otherwise). */
  async planOf(orgId: string): Promise<Plan> {
    const prof = await this.db.orgs.get(PLATFORM_ORG, orgId);
    return prof?.plan ?? ((process.env.DEFAULT_PLAN as Plan | undefined) ?? 'enterprise');
  }
  async has(orgId: string, f: Feature) { return PLAN_FEATURES[await this.planOf(orgId)].has(f); }
  async assertFeature(orgId: string, f: Feature) {
    if (!(await this.has(orgId, f))) throw new HttpException({ message: `feature "${f}" is not included in the current plan`, feature: f, plan: await this.planOf(orgId) }, HttpStatus.PAYMENT_REQUIRED);
  }
  async assertWithin(orgId: string, key: LimitKey, current: number) {
    const plan = await this.planOf(orgId), max = PLAN_LIMITS[plan][key];
    if (current >= max) throw new HttpException({ message: `plan limit reached for ${key} (${max})`, limit: key, max, plan }, HttpStatus.PAYMENT_REQUIRED);
  }
  async describe(orgId: string) {
    const plan = await this.planOf(orgId);
    return { plan, features: [...PLAN_FEATURES[plan]], limits: Object.fromEntries(Object.entries(PLAN_LIMITS[plan]).map(([k, v]) => [k, Number.isFinite(v) ? v : null])) };
  }
}
