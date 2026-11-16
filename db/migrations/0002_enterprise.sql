-- 0002_enterprise: users/sessions/roles, CTEM, IAM, signals/correlation/cases/evidence, SOAR, notifications, connectors, reports.
-- Same model as the baseline: JSONB document + generated columns for constraints/indexes + FORCE ROW LEVEL SECURITY per organisation.
DO $$ DECLARE t text; BEGIN
  FOREACH t IN ARRAY ARRAY['org_profile','user_account','auth_session','custom_role','password_reset','org_setting','inventory_asset','asset_relation','vulnerability','intel_record',
    'exposure_finding','exposure_event','identity','identity_change','signal','correlation','security_case','evidence_item','playbook','playbook_run','lab_effect','ticket',
    'notification_channel','notification_log','connector','connector_run','report'] LOOP
    EXECUTE format('CREATE TABLE IF NOT EXISTS %I (id text PRIMARY KEY, org_id text NOT NULL REFERENCES organization(id), doc jsonb NOT NULL, updated_at timestamptz NOT NULL DEFAULT now())', t);
    EXECUTE format('CREATE INDEX IF NOT EXISTS %I ON %I USING gin (doc jsonb_path_ops)', t || '_doc_gin', t);
    EXECUTE format('CREATE INDEX IF NOT EXISTS %I ON %I (org_id, updated_at DESC)', t || '_org_upd', t);
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON %I', t);
    EXECUTE format('CREATE POLICY tenant_isolation ON %I USING (org_id = current_setting(''app.org_id'', true)) WITH CHECK (org_id = current_setting(''app.org_id'', true))', t);
  END LOOP;
END $$;

-- Uniqueness the application relies on (races between replicas are decided here).
ALTER TABLE user_account ADD COLUMN IF NOT EXISTS email text GENERATED ALWAYS AS (lower(doc->>'email')) STORED;
CREATE UNIQUE INDEX IF NOT EXISTS user_email_per_org ON user_account (org_id, email);
ALTER TABLE inventory_asset ADD COLUMN IF NOT EXISTS ident text GENERATED ALWAYS AS ((doc->>'type') || ':' || lower(doc->>'identifier')) STORED;
CREATE UNIQUE INDEX IF NOT EXISTS inventory_ident_per_org ON inventory_asset (org_id, ident);
ALTER TABLE vulnerability ADD COLUMN IF NOT EXISTS fingerprint text GENERATED ALWAYS AS (doc->>'fingerprint') STORED;
ALTER TABLE vulnerability ADD COLUMN IF NOT EXISTS status text GENERATED ALWAYS AS (doc->>'status') STORED;
CREATE UNIQUE INDEX IF NOT EXISTS vuln_open_fp ON vulnerability (org_id, fingerprint) WHERE status NOT IN ('resolved');
ALTER TABLE intel_record ADD COLUMN IF NOT EXISTS cve text GENERATED ALWAYS AS (doc->>'cve') STORED;
CREATE UNIQUE INDEX IF NOT EXISTS intel_cve_per_org ON intel_record (org_id, cve);
ALTER TABLE exposure_finding ADD COLUMN IF NOT EXISTS fingerprint text GENERATED ALWAYS AS (doc->>'fingerprint') STORED;
ALTER TABLE exposure_finding ADD COLUMN IF NOT EXISTS status text GENERATED ALWAYS AS (doc->>'status') STORED;
CREATE UNIQUE INDEX IF NOT EXISTS exposure_open_fp ON exposure_finding (org_id, fingerprint) WHERE status = 'open';
ALTER TABLE signal ADD COLUMN IF NOT EXISTS dedup_key text GENERATED ALWAYS AS (doc->>'dedupKey') STORED;
CREATE UNIQUE INDEX IF NOT EXISTS signal_dedup_per_org ON signal (org_id, dedup_key);
ALTER TABLE security_case ADD COLUMN IF NOT EXISTS number bigint GENERATED ALWAYS AS ((doc->>'number')::bigint) STORED;
CREATE UNIQUE INDEX IF NOT EXISTS case_number_per_org ON security_case (org_id, number);
ALTER TABLE playbook ADD COLUMN IF NOT EXISTS pb_key text GENERATED ALWAYS AS (doc->>'key') STORED;
ALTER TABLE playbook ADD COLUMN IF NOT EXISTS version int GENERATED ALWAYS AS ((doc->>'version')::int) STORED;
CREATE UNIQUE INDEX IF NOT EXISTS playbook_version ON playbook (org_id, pb_key, version);
ALTER TABLE org_setting ADD COLUMN IF NOT EXISTS skey text GENERATED ALWAYS AS (doc->>'key') STORED;
CREATE UNIQUE INDEX IF NOT EXISTS setting_key_per_org ON org_setting (org_id, skey);

-- Append-only history tables, immutable playbook versions and immutable evidence content.
DROP TRIGGER IF EXISTS identity_change_immutable ON identity_change;
CREATE TRIGGER identity_change_immutable BEFORE UPDATE OR DELETE ON identity_change FOR EACH ROW EXECUTE FUNCTION forbid_mutation();
DROP TRIGGER IF EXISTS exposure_event_immutable ON exposure_event;
CREATE TRIGGER exposure_event_immutable BEFORE UPDATE OR DELETE ON exposure_event FOR EACH ROW EXECUTE FUNCTION forbid_mutation();
DROP TRIGGER IF EXISTS playbook_immutable ON playbook;
CREATE TRIGGER playbook_immutable BEFORE UPDATE OR DELETE ON playbook FOR EACH ROW EXECUTE FUNCTION forbid_mutation();
CREATE OR REPLACE FUNCTION evidence_guard() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
  IF TG_OP = 'DELETE' THEN RAISE EXCEPTION 'evidence cannot be deleted'; END IF;
  IF (OLD.doc->>'sha256') IS DISTINCT FROM (NEW.doc->>'sha256') OR (OLD.doc->>'objectKey') IS DISTINCT FROM (NEW.doc->>'objectKey') OR (OLD.doc->>'caseId') IS DISTINCT FROM (NEW.doc->>'caseId')
  THEN RAISE EXCEPTION 'evidence content reference is immutable'; END IF;
  RETURN NEW; END $$;
DROP TRIGGER IF EXISTS evidence_immutable ON evidence_item;
CREATE TRIGGER evidence_immutable BEFORE UPDATE OR DELETE ON evidence_item FOR EACH ROW EXECUTE FUNCTION evidence_guard();

-- The app role cannot DELETE, except on transient tables that retention/erasure must purge.
GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA public TO sentinel_app;
GRANT DELETE ON signal, notification_log, auth_session, password_reset, connector_run, exposure_finding TO sentinel_app;
