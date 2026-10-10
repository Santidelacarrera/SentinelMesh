-- Least-privilege application role: cannot bypass RLS, cannot DELETE (audit trail and workflow versions stay append-only).
-- Set the password through your secret manager; the dev compose file uses a throwaway value.
DO $$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'sentinel_app') THEN
    CREATE ROLE sentinel_app LOGIN PASSWORD 'dev-only-app' NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
  END IF;
END $$;
GRANT USAGE ON SCHEMA public TO sentinel_app;
GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA public TO sentinel_app;
