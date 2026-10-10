-- SentinelMesh PostgreSQL schema (target persistence; the runnable MVP uses the in-memory store behind the same org-scoped API).
-- Multi-tenancy: every table carries org_id and is protected by Row Level Security keyed on `SET app.org_id = '<org>'`.
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE organization (id text PRIMARY KEY, name text NOT NULL);
CREATE TABLE app_user (
  id text PRIMARY KEY, org_id text NOT NULL REFERENCES organization(id), email text NOT NULL,
  role text NOT NULL CHECK (role IN ('viewer','analyst','approver','admin')), UNIQUE (org_id, email));

CREATE TABLE vulnerability_scan (
  id text PRIMARY KEY, org_id text NOT NULL REFERENCES organization(id), source text NOT NULL, format text NOT NULL,
  report_ref text NOT NULL, report_sha256 text NOT NULL, finding_count int NOT NULL DEFAULT 0, created_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE asset_context (
  id text PRIMARY KEY, org_id text NOT NULL REFERENCES organization(id), name text NOT NULL, internet_facing boolean NOT NULL,
  behind_gateway boolean NOT NULL, handles_critical_data boolean NOT NULL, environment text NOT NULL, UNIQUE (org_id, name));
CREATE TABLE finding (
  id text PRIMARY KEY, org_id text NOT NULL REFERENCES organization(id), scan_id text NOT NULL REFERENCES vulnerability_scan(id),
  kind text NOT NULL CHECK (kind IN ('vulnerability','secret')), fingerprint text NOT NULL, rule_id text NOT NULL, title text NOT NULL, description text NOT NULL,
  base_severity text NOT NULL, severity text NOT NULL, exposure_score int NOT NULL, asset_name text, location text,
  status text NOT NULL CHECK (status IN ('open','suppressed','remediating','resolved')), suppression_reason text, rationale jsonb NOT NULL DEFAULT '[]',
  masked_secret text,  -- only the masked form is ever persisted
  credential_id text, created_at timestamptz NOT NULL DEFAULT now());
CREATE UNIQUE INDEX finding_open_fp ON finding (org_id, fingerprint) WHERE status <> 'resolved';

CREATE TABLE credential_record (
  id text PRIMARY KEY, org_id text NOT NULL REFERENCES organization(id), name text NOT NULL, service text NOT NULL,
  kind text NOT NULL CHECK (kind IN ('api_key','master_secret')), current_version int NOT NULL, masked_value text NOT NULL,
  status text NOT NULL CHECK (status IN ('active','exposed','revoked')), healthcheck_url text);
CREATE TABLE identity_audit (
  id text PRIMARY KEY, org_id text NOT NULL REFERENCES organization(id), role_name text NOT NULL, critical boolean NOT NULL,
  granted jsonb NOT NULL, used jsonb NOT NULL, unused jsonb NOT NULL, usage_ratio numeric NOT NULL, proposed_policy jsonb NOT NULL, created_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE access_policy (id text PRIMARY KEY, org_id text NOT NULL REFERENCES organization(id), role_name text NOT NULL, policy jsonb NOT NULL, version int NOT NULL);

CREATE TABLE traffic_anomaly (
  id text PRIMARY KEY, org_id text NOT NULL REFERENCES organization(id), kind text NOT NULL, source text NOT NULL, target text NOT NULL,
  count bigint NOT NULL, window_sec int NOT NULL, created_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE security_incident (
  id text PRIMARY KEY, org_id text NOT NULL REFERENCES organization(id), anomaly_id text NOT NULL REFERENCES traffic_anomaly(id), severity text NOT NULL,
  target text NOT NULL, status text NOT NULL, summary text, snapshot_id text, execution_id text, created_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE forensic_snapshot (
  id text PRIMARY KEY, org_id text NOT NULL REFERENCES organization(id), incident_id text NOT NULL REFERENCES security_incident(id),
  object_key text NOT NULL, sha256 text NOT NULL, items jsonb NOT NULL, captured_at timestamptz NOT NULL DEFAULT now());

-- Workflow definitions are immutable per version.
CREATE TABLE security_workflow (
  id text PRIMARY KEY, org_id text NOT NULL REFERENCES organization(id), key text NOT NULL, version int NOT NULL,
  steps jsonb NOT NULL, content_hash text NOT NULL, created_at timestamptz NOT NULL DEFAULT now(), UNIQUE (org_id, key, version));
CREATE TABLE dry_run_plan (
  id text PRIMARY KEY, org_id text NOT NULL REFERENCES organization(id), kind text NOT NULL, target_ref text NOT NULL, action text NOT NULL,
  params jsonb NOT NULL, diff text NOT NULL, terraform text, plan_hash text NOT NULL, destructive boolean NOT NULL, applied boolean NOT NULL DEFAULT false,
  source_finding_id text, created_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE workflow_execution (
  id text PRIMARY KEY, org_id text NOT NULL REFERENCES organization(id), workflow_id text NOT NULL REFERENCES security_workflow(id),
  status text NOT NULL, context jsonb NOT NULL, steps jsonb NOT NULL, incident_id text, created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE secops_approval (
  id text PRIMARY KEY, org_id text NOT NULL REFERENCES organization(id), execution_id text NOT NULL REFERENCES workflow_execution(id), step_name text NOT NULL,
  plan_id text NOT NULL REFERENCES dry_run_plan(id), plan_hash text NOT NULL, status text NOT NULL CHECK (status IN ('pending','approved','rejected')),
  requested_at timestamptz NOT NULL DEFAULT now(), decided_by text, decided_at timestamptz, comment text, signature text,
  UNIQUE (execution_id, step_name));

-- Append-only, hash-chained audit trail.
CREATE TABLE audit_trail (
  id text PRIMARY KEY, org_id text NOT NULL REFERENCES organization(id), seq bigint NOT NULL, at timestamptz NOT NULL, actor text NOT NULL,
  event text NOT NULL, data jsonb NOT NULL, prev_hash text NOT NULL, hash text NOT NULL, UNIQUE (org_id, seq));
CREATE FUNCTION forbid_mutation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION '% is append-only', TG_TABLE_NAME; END $$;
CREATE TRIGGER audit_immutable BEFORE UPDATE OR DELETE ON audit_trail FOR EACH ROW EXECUTE FUNCTION forbid_mutation();
CREATE TRIGGER workflow_immutable BEFORE UPDATE OR DELETE ON security_workflow FOR EACH ROW EXECUTE FUNCTION forbid_mutation();

-- Row Level Security: the app role can only see its own organisation.
DO $$ DECLARE t text; BEGIN
  FOREACH t IN ARRAY ARRAY['app_user','vulnerability_scan','asset_context','finding','credential_record','identity_audit','access_policy','traffic_anomaly',
    'security_incident','forensic_snapshot','security_workflow','dry_run_plan','workflow_execution','secops_approval','audit_trail'] LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('CREATE POLICY tenant_isolation ON %I USING (org_id = current_setting(''app.org_id'', true)) WITH CHECK (org_id = current_setting(''app.org_id'', true))', t);
  END LOOP;
END $$;
