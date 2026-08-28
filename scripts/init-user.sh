#!/usr/bin/env bash
set -e

APP_USER="${KMS_APP_USER:-kms_app_user}"
APP_PASSWORD=$(cat /run/secrets/kms_app_db_pass)
TARGET_DB="${POSTGRES_DB:-kms_db}"

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
    DO \$\$
    BEGIN
        IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = '$APP_USER') THEN
            CREATE USER $APP_USER WITH PASSWORD '$APP_PASSWORD';
        END IF;
    END
    \$\$;

    GRANT ALL PRIVILEGES ON DATABASE $TARGET_DB TO $APP_USER;
EOSQL