-- Least-privilege application role: cannot bypass RLS, cannot DELETE (audit trail and workflow versions stay append-only).
-- Set the password through your secret manager; the dev compose file uses a throwaway value.
DO $$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'sentinel_app') THEN
    CREATE ROLE sentinel_app LOGIN PASSWORD 'dev-only-app' NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
  END IF;
END $$;
GRANT USAGE ON SCHEMA public TO sentinel_app;
GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA public TO sentinel_app;
-- Tables created by later migrations that retention/erasure must be able to purge (no-op if a migration has not run yet).
DO $$ DECLARE t text; BEGIN
  FOREACH t IN ARRAY ARRAY['signal','notification_log','auth_session','password_reset','connector_run','exposure_finding'] LOOP
    IF to_regclass('public.' || t) IS NOT NULL THEN EXECUTE format('GRANT DELETE ON %I TO sentinel_app', t); END IF;
  END LOOP;
END $$;
