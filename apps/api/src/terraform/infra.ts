import { ApprovalProof, InfraAdapter } from '../workflow/ports';
import { DryRunPlan } from '../store/models';
import { TerminalStepError } from '../workflow/errors';
import { TerraformPlanner } from './planner';

type ProofCheck = (p: ApprovalProof) => void | Promise<void>;

/**
 * waf/iam plans that carry a saved Terraform plan are applied with `terraform apply <that plan>`: exactly the reviewed change.
 * Everything else (isolation, or Terraform disabled) goes to the delegate (AWS SDK adapter).
 */
export class TerraformInfraAdapter implements InfraAdapter {
  constructor(private delegate: InfraAdapter, private planner: TerraformPlanner, private proofCheck: ProofCheck) {}

  private async viaTerraform(proof: ApprovalProof, plan: DryRunPlan) {
    await this.proofCheck(proof);
    if (proof.planId !== plan.id || proof.planHash !== plan.planHash) throw new TerminalStepError('approval was signed for a different plan');
    const r = await this.planner.apply(plan);
    return { ref: r.ref };
  }
  async applyWafRule(params: Record<string, unknown>, proof: ApprovalProof, plan?: DryRunPlan) {
    return plan?.tf?.planRef ? this.viaTerraform(proof, plan) : this.delegate.applyWafRule(params, proof, plan);
  }
  async applyIamPolicy(params: Record<string, unknown>, proof: ApprovalProof, plan?: DryRunPlan) {
    return plan?.tf?.planRef ? this.viaTerraform(proof, plan) : this.delegate.applyIamPolicy(params, proof, plan);
  }
  isolateService(target: string, proof: ApprovalProof, plan?: DryRunPlan) { return this.delegate.isolateService(target, proof, plan); }
}
