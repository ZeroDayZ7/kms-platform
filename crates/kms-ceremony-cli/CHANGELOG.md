# Changelog

## Unreleased

- Added service-level HMAC signing for audit verification requests with lowercase hex signatures and canonical `METHOD:PATH:TIMESTAMP` payloads.
- Added environment-based CLI config for service ID, secret, and service URL with fail-fast validation for authenticated calls.
