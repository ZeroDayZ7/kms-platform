-- 003_grant_permissions.sql
-- Upewnienie się, że kms_app_user ma odpowiednie prawa do tabel
GRANT SELECT, INSERT, UPDATE ON TABLE keys TO kms_app_user;
GRANT SELECT, INSERT ON TABLE audit_logs TO kms_app_user;