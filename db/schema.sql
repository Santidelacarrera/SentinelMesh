-- SentinelMesh PostgreSQL schema.
-- Each aggregate is stored as a JSONB document (`doc`) plus GENERATED columns that carry the constraints/indexes we rely on.
-- Multi-tenancy: every table has org_id and FORCE ROW LEVEL SECURITY keyed on `set_config('app.org_id', <org>, true)`.
-- The application must connect as a role that is neither superuser nor BYPASSRLS (see the sentinel_app role below).
CREATE TABLE IF NOT EXISTS organization (id text PRIMARY KEY, name text);

DO $$ DECLARE t text; BEGIN
  FOREACH t IN ARRAY ARRAY['vulnerability_scan','asset_context','finding','credential_record','identity_audit','access_policy','traffic_anomaly',
    'security_incident','forensic_snapshot','security_workflow','dry_run_plan','workflow_execution','secops_approval'] LOOP
    EXECUTE format('CREATE TABLE IF NOT EXISTS %I (id text PRIMARY KEY, org_id text NOT NULL REFERENCES organization(id), doc jsonb NOT NULL, updated_at timestamptz NOT NULL DEFAULT now())', t);
  END LOOP;
END $$;

-- Constraints/indexes on document fields via generated columns (idempotent).
ALTER TABLE finding ADD COLUMN IF NOT EXISTS status text GENERATED ALWAYS AS (doc->>'status') STORED CHECK (status IN ('open','suppressed','remediating','resolved'));
ALTER TABLE finding ADD COLUMN IF NOT EXISTS fingerprint text GENERATED ALWAYS AS (doc->>'fingerprint') STORED;
CREATE UNIQUE INDEX IF NOT EXISTS finding_open_fp ON finding (org_id, fingerprint) WHERE status <> 'resolved';
ALTER TABLE secops_approval ADD COLUMN IF NOT EXISTS status text GENERATED ALWAYS AS (doc->>'status') STORED CHECK (status IN ('pending','approved','rejected'));
ALTER TABLE secops_approval ADD COLUMN IF NOT EXISTS execution_id text GENERATED ALWAYS AS (doc->>'executionId') STORED;
ALTER TABLE secops_approval ADD COLUMN IF NOT EXISTS step_name text GENERATED ALWAYS AS (doc->>'stepName') STORED;
CREATE UNIQUE INDEX IF NOT EXISTS approval_per_step ON secops_approval (execution_id, step_name);
ALTER TABLE workflow_execution ADD COLUMN IF NOT EXISTS status text GENERATED ALWAYS AS (doc->>'status') STORED;
ALTER TABLE security_workflow ADD COLUMN IF NOT EXISTS wf_key text GENERATED ALWAYS AS (doc->>'key') STORED;
ALTER TABLE security_workflow ADD COLUMN IF NOT EXISTS version int GENERATED ALWAYS AS ((doc->>'version')::int) STORED;
CREATE UNIQUE INDEX IF NOT EXISTS workflow_version ON security_workflow (org_id, wf_key, version);
ALTER TABLE dry_run_plan ADD COLUMN IF NOT EXISTS plan_hash text GENERATED ALWAYS AS (doc->>'planHash') STORED;

-- Containment index for `doc @> {...}` lookups used by the repositories.
DO $$ DECLARE t text; BEGIN
  FOREACH t IN ARRAY ARRAY['vulnerability_scan','asset_context','finding','credential_record','identity_audit','access_policy','traffic_anomaly',
    'security_incident','forensic_snapshot','security_workflow','dry_run_plan','workflow_execution','secops_approval'] LOOP
    EXECUTE format('CREATE INDEX IF NOT EXISTS %I ON %I USING gin (doc jsonb_path_ops)', t || '_doc_gin', t);
    EXECUTE format('CREATE INDEX IF NOT EXISTS %I ON %I (org_id, updated_at DESC)', t || '_org_upd', t);
  END LOOP;
END $$;

-- Append-only, hash-chained audit trail (columns kept typed: it is the compliance record).
CREATE TABLE IF NOT EXISTS audit_trail (
  id text PRIMARY KEY, org_id text NOT NULL REFERENCES organization(id), seq bigint NOT NULL, at timestamptz NOT NULL, actor text NOT NULL,
  event text NOT NULL, data jsonb NOT NULL, prev_hash text NOT NULL, hash text NOT NULL, UNIQUE (org_id, seq));
CREATE OR REPLACE FUNCTION forbid_mutation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION '% is append-only', TG_TABLE_NAME; END $$;
DROP TRIGGER IF EXISTS audit_immutable ON audit_trail;
CREATE TRIGGER audit_immutable BEFORE UPDATE OR DELETE ON audit_trail FOR EACH ROW EXECUTE FUNCTION forbid_mutation();
-- Published workflow versions are immutable: UPDATE is rejected too.
DROP TRIGGER IF EXISTS workflow_immutable ON security_workflow;
CREATE TRIGGER workflow_immutable BEFORE UPDATE OR DELETE ON security_workflow FOR EACH ROW EXECUTE FUNCTION forbid_mutation();

DO $$ DECLARE t text; BEGIN
  FOREACH t IN ARRAY ARRAY['vulnerability_scan','asset_context','finding','credential_record','identity_audit','access_policy','traffic_anomaly',
    'security_incident','forensic_snapshot','security_workflow','dry_run_plan','workflow_execution','secops_approval','audit_trail'] LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON %I', t);
    EXECUTE format('CREATE POLICY tenant_isolation ON %I USING (org_id = current_setting(''app.org_id'', true)) WITH CHECK (org_id = current_setting(''app.org_id'', true))', t);
  END LOOP;
END $$;
-- `organization` is only readable/insertable by the app role (no tenant data in it); create the least-privilege role:
-- CREATE ROLE sentinel_app LOGIN PASSWORD '…' NOSUPERUSER NOBYPASSRLS;  GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA public TO sentinel_app;
