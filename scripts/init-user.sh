#!/usr/bin/env bash
set -e

MIGRATOR_USER="${POSTGRES_MIGRATOR_USER:-kms_migrator_user}"
MIGRATOR_PASSWORD=$(cat /run/secrets/kms_migrator_db_pass)

APP_USER="${POSTGRES_APP_USER:-kms_app_user}"
APP_PASSWORD=$(cat /run/secrets/kms_app_db_pass)

TARGET_DB="${POSTGRES_DB:-kms_db}"

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$TARGET_DB" <<-EOSQL
    -- 1. Tworzenie użytkowników jeśli nie istnieją
    DO \$\$
    BEGIN
        IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = '$MIGRATOR_USER') THEN
            CREATE USER $MIGRATOR_USER WITH PASSWORD '$MIGRATOR_PASSWORD';
        END IF;

        IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = '$APP_USER') THEN
            CREATE USER $APP_USER WITH PASSWORD '$APP_PASSWORD';
        END IF;
    END
    \$\$;

    -- 2. Uprawnienia dla MIGRATORA (właściciel schematu, tworzy DDL)
    GRANT ALL PRIVILEGES ON DATABASE $TARGET_DB TO $MIGRATOR_USER;
    ALTER SCHEMA public OWNER TO $MIGRATOR_USER;
    GRANT ALL ON SCHEMA public TO $MIGRATOR_USER;

    -- 3. Uprawnienia dla APLIKACJI (tylko połączenie i operacje DML)
    GRANT CONNECT ON DATABASE $TARGET_DB TO $APP_USER;
    GRANT USAGE ON SCHEMA public TO $APP_USER;

    -- 4. Automatyczne nadawanie praw DML na nowe tabele tworzone przez migratora
    ALTER DEFAULT PRIVILEGES FOR ROLE $MIGRATOR_USER IN SCHEMA public
        GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO $APP_USER;

    ALTER DEFAULT PRIVILEGES FOR ROLE $MIGRATOR_USER IN SCHEMA public
        GRANT USAGE, SELECT ON SEQUENCES TO $APP_USER;
EOSQL