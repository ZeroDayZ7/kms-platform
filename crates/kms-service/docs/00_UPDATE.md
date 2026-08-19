# Dependency Update Guide

### 1. Setup Tools
Install the necessary extensions for managing dependencies:
```bash
# For upgrading Cargo.toml versions
cargo install cargo-edit

# For viewing outdated packages
cargo install cargo-outdated
```

### 2. Check for Updates
To see which packages are out of date:
```bash
cargo outdated
```

### 3. Apply Updates
* **Safe update** (updates `Cargo.lock` within SemVer):
    ```bash
    cargo update
    ```
* **Aggressive update** (rewrites `Cargo.toml` to the latest versions):
    ```bash
    cargo upgrade
    ```
* **note: pass `--verbose` to see 3 unchanged dependencies behind latest**
cargo update --verbose

### 4. Verify
Always run tests after updating:
```bash
cargo test
```