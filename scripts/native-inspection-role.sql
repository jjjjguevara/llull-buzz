-- Maintained, opt-in native Buzz database admission. NOT a provider migration.
-- Operator review/provisioning only; this file is never executed by the inspector.
-- Run against the admitted native writer database as its authorized administrator.
-- No passwords, shared PUBLIC revocations, existing-role changes or test tables.
-- psql --set=runtime_role=THE_ADMITTED_APPLICATION_ROLE --file=... (operator only).
\set ON_ERROR_STOP on
\if :{?runtime_role}
\else
  \echo 'runtime_role must name the already admitted application role'
  \quit 3
\endif
BEGIN;
DO $$
BEGIN
  IF current_setting('server_version_num')::integer < 150000
     OR pg_is_in_recovery()
     OR to_regclass('public.relay_members') IS NULL THEN
    RAISE EXCEPTION 'native writer/schema prerequisite missing';
  END IF;
  IF EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname='buzz_native_recovery_inspector') THEN
    RAISE EXCEPTION 'existing role requires separate reviewed admission, never replace it';
  END IF;
  IF NOT EXISTS (SELECT FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
      WHERE n.nspname='public' AND c.relname='relay_members' AND c.relkind='r'
        AND NOT c.relrowsecurity AND NOT c.relforcerowsecurity)
     OR EXISTS (SELECT FROM pg_catalog.pg_inherits WHERE inhrelid='public.relay_members'::regclass OR inhparent='public.relay_members'::regclass)
     OR (SELECT count(*) FROM pg_catalog.pg_attribute WHERE attrelid='public.relay_members'::regclass AND attnum>0 AND NOT attisdropped) <> 6
     OR (SELECT array_agg(attname::text||':'||atttypid::text||':'||attnotnull::text ORDER BY attnum)
         FROM pg_catalog.pg_attribute WHERE attrelid='public.relay_members'::regclass AND attnum>0 AND NOT attisdropped)
        IS DISTINCT FROM ARRAY['community_id:2950:true','pubkey:25:true','role:25:true','added_by:25:false','created_at:1184:true','updated_at:1184:true']
     OR NOT EXISTS (SELECT FROM pg_catalog.pg_index WHERE indrelid='public.relay_members'::regclass
        AND indisprimary AND indisunique AND indisvalid AND indisready
        AND indkey::text='1 2'
        AND indcollation[0]=0 AND indcollation[1]=(SELECT attcollation FROM pg_catalog.pg_attribute WHERE attrelid='public.relay_members'::regclass AND attname='pubkey' AND NOT attisdropped))
     OR EXISTS (SELECT FROM pg_catalog.pg_collation c WHERE NOT c.collisdeterministic AND c.oid IN (
        SELECT a.attcollation FROM pg_catalog.pg_attribute a WHERE a.attrelid='public.relay_members'::regclass AND a.attnum>0 AND NOT a.attisdropped
        UNION SELECT unnest(i.indcollation) FROM pg_catalog.pg_index i WHERE i.indrelid='public.relay_members'::regclass)) THEN
    RAISE EXCEPTION 'actual upstream relay_members table/primary-key prerequisite missing';
  END IF;
END $$;
-- This existing application setting is a prerequisite, not authority to change
-- the application role here. It pins unqualified FROM relay_members resolution.
SELECT EXISTS (
  SELECT FROM pg_catalog.pg_roles r JOIN pg_catalog.pg_db_role_setting s ON s.setrole=r.oid
  WHERE r.rolname=:'runtime_role' AND s.setdatabase=(SELECT oid FROM pg_catalog.pg_database WHERE datname=current_database())
    AND s.setconfig @> ARRAY['search_path=pg_catalog, public']
    AND (SELECT count(*) FROM unnest(s.setconfig) setting WHERE setting LIKE 'search_path=%')=1
) AS native_runtime_search_path_ready \gset
\if :native_runtime_search_path_ready
\else
  \echo 'runtime role-in-database search_path=pg_catalog, public prerequisite missing; separate owner authority is required'
  \quit 3
\endif
CREATE ROLE buzz_native_recovery_inspector LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
  NOINHERIT NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 2;
SELECT format('GRANT CONNECT ON DATABASE %I TO buzz_native_recovery_inspector',current_database()) \gexec
GRANT USAGE ON SCHEMA public TO buzz_native_recovery_inspector;
GRANT SELECT ON TABLE public.relay_members TO buzz_native_recovery_inspector;
GRANT EXECUTE ON FUNCTION pg_catalog.pg_control_system() TO buzz_native_recovery_inspector;
ALTER ROLE buzz_native_recovery_inspector SET default_transaction_read_only=on;
ALTER ROLE buzz_native_recovery_inspector SET search_path=pg_catalog,public;
ALTER ROLE buzz_native_recovery_inspector SET statement_timeout='20s';
ALTER ROLE buzz_native_recovery_inspector SET lock_timeout='1s';
DO $$
BEGIN
  -- PostgreSQL has no per-role DENY against a PUBLIC grant. Refuse the entire
  -- transaction if existing shared rights would make this role writable. An
  -- owner must resolve such prerequisites under separate explicit authority.
  IF has_database_privilege('buzz_native_recovery_inspector',current_database(),'CREATE')
     OR has_database_privilege('buzz_native_recovery_inspector',current_database(),'TEMPORARY')
     OR EXISTS (SELECT FROM pg_catalog.pg_namespace WHERE left(nspname,3)<>'pg_' AND nspname<>'information_schema'
        AND has_schema_privilege('buzz_native_recovery_inspector',oid,'CREATE'))
     OR EXISTS (SELECT FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
        WHERE left(n.nspname,3)<>'pg_' AND n.nspname<>'information_schema'
        AND has_function_privilege('buzz_native_recovery_inspector',p.oid,'EXECUTE'))
     OR EXISTS (SELECT FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
        WHERE left(n.nspname,3)<>'pg_' AND n.nspname<>'information_schema' AND c.relkind IN ('r','p','v','m','f')
        AND (has_table_privilege('buzz_native_recovery_inspector',c.oid,'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
          OR (c.oid<>'public.relay_members'::regclass AND has_any_column_privilege('buzz_native_recovery_inspector',c.oid,'SELECT'))
          OR has_any_column_privilege('buzz_native_recovery_inspector',c.oid,'INSERT,UPDATE,REFERENCES')))
     OR EXISTS (SELECT FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
        WHERE left(n.nspname,3)<>'pg_' AND n.nspname<>'information_schema' AND c.relkind='S'
        AND has_sequence_privilege('buzz_native_recovery_inspector',c.oid,'USAGE,UPDATE')) THEN
    RAISE EXCEPTION 'native read-only admission refused: preexisting shared privileges require separately approved remediation';
  END IF;
END $$;
COMMIT;
-- Provision this new role's password or certificate mapping separately in its
-- approved credential channel. Capture actual OIDs/system_identifier/TLS root,
-- complete fixed catalog bytes/digest and process admission into the root-signed
-- private profile; never infer them from this source recipe or a successful DDL.
