import { Provider } from '@nestjs/common';
import { SecretsManagerClient } from '@aws-sdk/client-secrets-manager';
import { WAFV2Client } from '@aws-sdk/client-wafv2';
import { IAMClient } from '@aws-sdk/client-iam';
import { EC2Client } from '@aws-sdk/client-ec2';
import { S3Client } from '@aws-sdk/client-s3';
import { ApprovalSigner } from './approvals/signer';
import { PORTS, SecretProvider } from './workflow/ports';
import { SimulatedForensics, SimulatedHealth, SimulatedInfra, SimulatedSecrets } from './workflow/simulated';
import { AwsInfraAdapter, AwsSecretProvider, S3ObjectStorage } from './adapters/aws';
import { HttpHealthChecker } from './adapters/health';
import { HttpForensicCollector } from './adapters/forensics';
import { FsObjectStorage, MemoryObjectStorage, OBJECT_STORAGE } from './storage/object-storage';

const json = <T>(v: string | undefined, d: T): T => (v ? JSON.parse(v) : d);
const aws = () => ({ region: process.env.AWS_REGION ?? 'us-east-1', endpoint: process.env.AWS_ENDPOINT_URL });
const real = () => process.env.INFRA_MODE === 'aws';

/**
 * INFRA_MODE=aws → real adapters (AWS Secrets Manager / WAFv2 / IAM / EC2 + HTTP probes + Prometheus/Loki/K8s).
 * Anything else → simulated ports, refused when NODE_ENV=production so a prod deploy can never silently "succeed" without effect.
 */
export const portProviders: Provider[] = [
  { provide: OBJECT_STORAGE, useFactory: () =>
    process.env.OBJECT_STORE_BUCKET ? new S3ObjectStorage(new S3Client({ ...aws(), forcePathStyle: !!process.env.AWS_ENDPOINT_URL }), process.env.OBJECT_STORE_BUCKET, process.env.OBJECT_STORE_PREFIX ?? '')
    : process.env.OBJECT_STORE_DIR ? new FsObjectStorage(process.env.OBJECT_STORE_DIR) : new MemoryObjectStorage() },
  { provide: PORTS.SECRETS, inject: [ApprovalSigner], useFactory: (s: ApprovalSigner): SecretProvider => {
    guard(); return real() ? new AwsSecretProvider(new SecretsManagerClient(aws()), (p) => s.assertProof(p)) : new SimulatedSecrets((p) => s.assertProof(p)); } },
  { provide: PORTS.HEALTH, inject: [PORTS.SECRETS], useFactory: (sp: SecretProvider) => !real() ? new SimulatedHealth() : new HttpHealthChecker({
    urls: json(process.env.HEALTHCHECK_URLS, {}), policy: { allowHttp: process.env.HEALTHCHECK_ALLOW_HTTP === '1', allowPrivateHosts: json(process.env.HEALTHCHECK_PRIVATE_HOSTS, []) },
    getSecret: (c, v) => (sp as AwsSecretProvider).getValue(c, v) }) },
  { provide: PORTS.INFRA, inject: [ApprovalSigner], useFactory: (s: ApprovalSigner) => !real() ? new SimulatedInfra((p) => s.assertProof(p))
    : new AwsInfraAdapter({ waf: new WAFV2Client(aws()), iam: new IAMClient(aws()), ec2: new EC2Client(aws()), proofCheck: (p) => s.assertProof(p), isolation: json(process.env.ISOLATION_TARGETS, {}), wafScope: (process.env.WAF_SCOPE as 'REGIONAL' | 'CLOUDFRONT') ?? 'REGIONAL' }) },
  { provide: PORTS.FORENSICS, useFactory: () => !real() ? new SimulatedForensics() : new HttpForensicCollector({
    prometheusUrl: process.env.PROMETHEUS_URL, lokiUrl: process.env.LOKI_URL, kubeApiUrl: process.env.KUBE_API_URL, kubeToken: process.env.KUBE_TOKEN, namespace: process.env.KUBE_NAMESPACE,
    policy: { allowHttp: process.env.FORENSICS_ALLOW_HTTP === '1', allowPrivateHosts: json(process.env.FORENSICS_PRIVATE_HOSTS, []) } }) },
];
function guard() { if (process.env.NODE_ENV === 'production' && !real()) throw new Error('NODE_ENV=production requires INFRA_MODE=aws (simulated ports are for dev/test only)'); }
