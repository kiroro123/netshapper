# Changelog

All notable changes to this project are documented in this file.

## [0.8.0] - 2026-06-10

### 🔴 Critical Security Improvements

#### Orchestrator Refactoring
- **BREAKING:** Split monolithic `orchestrator.py` (1,311 lines) into five independently auditable modules:
  - `authorization.py` — Authorization policy enforcement (immutable CIDR allowlist)
  - `firewall_manager.py` — Firewall rule lifecycle (iptables/ip6tables management)
  - `mitm_manager.py` — mitmproxy process control and lifecycle
  - `recovery_manager.py` — Stale session detection and atomic cleanup
  - Remaining `orchestrator.py` — Small glue layer (session lifecycle, sniffer, state)

  **Impact:** Reduces audit surface by making each subsystem independently reviewable and testable. Privilege escapes, firewall misconfigurations, and recovery logic are now isolated.

#### Authorization Enforcement
- Replaced mutable `list` `authorized_cidrs` with immutable `AuthorizationPolicy` / immutable `tuple`
- Prevents accidental mutation of authorization invariants
- Thread-safe access via read-only property

#### Error Handling
- Library modules no longer call `sys.exit()` directly
- New exception hierarchy (`exceptions.py`):
  - `NetShaperError` (base)
  - `SystemCheckError`, `PrivilegeError`, `DiscoveryError`, `InitializationError`, `InterfaceError`
- CLI layer now catches and handles exceptions with appropriate exit codes

### 🟠 High-Priority Improvements

#### Static Analysis Expansion
- **Mypy:** Coverage expanded from 3 files → all of `src/netshaper/`
- **Ruff:** Added `W` (warnings), `C` (complexity), `B` (bugbear) rules
- **Bandit:** Removed global skips; replaced with localized `# nosec` annotations with explanatory comments

#### Test Coverage
- Coverage threshold increased: 62% → 80%
- Isolated high-risk modules for 90%+ target:
  - `recovery_manager.py` (stale session cleanup)
  - `firewall_manager.py` (iptables operations)
  - `authorization.py` (CIDR validation)

#### Pre-Release Gate
- Added `.github/workflows/pre-release.yml`
- Enforces coverage ≥80% before merge
- Documents privileged test requirements

### 🟡 Medium-Priority Improvements

#### Captive Portal Refactoring
- New `captive_portal.py` with immutable configuration:
  - `DnsConfig` dataclass (spoof_all, smart_spoof_all, etc.)
  - `HTTPPortalConfig` dataclass (host_ip, ports, paths)
  - CLI args for hardcoded paths (--index-file, --ca-cert, etc.)
- Backward-compatible: `fake_server3.py` remains, new entry point `netshaper-captive-portal`
- Global mutable state eliminated

#### Security Documentation
- New `SECURITY.md`:
  - Known risks (unauthenticated /cert endpoint, privilege requirements)
  - Mitigation strategies
  - Audit procedures
  - Responsible disclosure process

#### README Enhancement
- Added architecture diagrams and component responsibilities
- Workflow flowchart (DNS→captive portal→HTTPS interception)
- Component isolation and audit surface explanation

### 🔵 Polish

#### Version
- Updated from 3.8.0 → 0.8.0 (reflects pre-release status)

#### Dependency Verification
- Confirmed scapy is actively used:
  - ARP sweep and host discovery
  - Packet capture and filtering
  - Packet construction for spoofing
  - Maintained as required dependency

#### Configuration (pyproject.toml)
- Extended mypy files glob to `src/netshaper/`
- Expanded ruff lint rules (warnings, complexity, bugbear)
- Added coverage exclusion patterns (repr, main, NotImplementedError)

### Migration Notes

**For users:**
- No breaking changes to CLI interface
- `fake_server3` continues to work; `netshaper-captive-portal` is preferred
- Verify authorized CIDRs with `--dry-run` before first run

**For developers:**
- Orchestrator import changes: modules now split, may need to import new managers directly
- Authorization checks now raise `AuthorizationError` instead of returning False
- Recovery now uses `RecoveryManager` class instead of orchestrator methods

**For auditors:**
- Five new independently auditable modules
- Each has clear responsibility and testable interface
- Stale session recovery is now isolated and reviewable
- Firewall rules are now centralized in `FirewallManager`

### Files Added
- `src/netshaper/exceptions.py` — Exception hierarchy
- `src/netshaper/core/authorization.py` — Authorization policy (immutable)
- `src/netshaper/core/firewall_manager.py` — Firewall lifecycle
- `src/netshaper/core/mitm_manager.py` — mitmproxy control
- `src/netshaper/core/recovery_manager.py` — Stale session recovery
- `src/netshaper/captive_portal.py` — Refactored captive portal with immutable configs
- `.github/workflows/pre-release.yml` — Gating for privileged tests
- `SECURITY.md` — Security risks and mitigation

### Files Modified
- `pyproject.toml` — Coverage, mypy, ruff, bandit configs; version; new script entry point
- `src/netshaper/core/orchestrator.py` — New imports, sys.exit() → exceptions
- `src/netshaper/system.py` — sys.exit() → exceptions, nosec annotations
- `src/netshaper/core/state_manager.py` — nosec annotations
- `src/netshaper/version.py` — 3.8.0 → 0.8.0
- `README.md` — Architecture, workflows, component details, security link
