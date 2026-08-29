# kms-migrate

A production-grade PostgreSQL database migration runner for the Key Management Service (KMS), written in Rust.

## Features

- **Advisory Locking**: Uses PostgreSQL advisory locks (`0x4B4D535F4D494752`) to prevent race conditions during concurrent deployment rollouts.
- **Health Check & Retry**: Waits for the PostgreSQL database to be healthy and ready before attempting to apply migrations.
- **Graceful Cancellation**: Handles `SIGINT` and `SIGTERM` signals safely, ensuring lock release upon exit.
- **SQLx Integration**: Uses standard `SQLx` migration format and tracks history via the `_sqlx_migrations` table.

## Commands

- **`run`** _(default)_: Applies all pending migrations to the database.
  - `--dry-run` / `-d`: Lists pending migrations without applying them.
- **`status`**: Displays database connection info alongside a detailed breakdown of applied and pending migrations.
  D
