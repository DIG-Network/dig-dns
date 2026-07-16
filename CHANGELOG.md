# Changelog

All notable changes to this project are documented here.
This project adheres to [Semantic Versioning](https://semver.org) and
[Conventional Commits](https://www.conventionalcommits.org).

## [0.14.0] - 2026-07-16

### Features
- **os-config:** Activate OS DNS live at configure-os (flush + verify) (#22)

## [0.13.2] - 2026-07-15

### CI
- **release:** Nightlies system (cron + dispatch, nightly channel) (#592) (#20)- **release:** Nightlies polish (#21)

## [0.13.0] - 2026-07-14

### Features
- **dns:** Resolve dig-dns's own rpc.dig.net lookup over encrypted DNS (#19)

## [0.12.0] - 2026-07-14

### Features
- **cli:** Digd first-class alias binary for dig-dns (mirror digs #434) (#18)

## [0.11.1] - 2026-07-13

### Bug Fixes
- Repair malformed XML comment in wix/main.wxs breaking MSI build (#530) (#17)

## [0.11.0] - 2026-07-13

### Features
- Configure-os/unconfigure-os OS resolver wiring + native-package hooks (#530) (#16)

## [0.10.2] - 2026-07-13

### Bug Fixes
- Generate .deb systemd enable/start scripts + fix msi/deb release smoke tests (#15)

## [0.10.1] - 2026-07-13

### Testing
- Add 3-OS service-smoke CI + wire the shared DIG_NODE_PORT constant (#14)

## [0.10.0] - 2026-07-13

### Features
- Native OS install packages (.msi/.pkg/.deb) self-installing the service (#503) (#13)

## [0.9.1] - 2026-07-13

### Testing
- Cover serve_with_shutdown end-to-end (runtime.json record + clear) (#12)

## [0.9.0] - 2026-07-13

### Bug Fixes
- Report SERVICE_RUNNING before startup work; CLI targets running service (#499, #501) (#11)

## [0.8.0] - 2026-07-13

### Features
- Canonical service identity + clean-reinstall (#10)

## [0.7.2] - 2026-07-12

### Bug Fixes
- **deps:** Re-pin DIG git deps to rewritten (co-author history) revs- **deps:** Re-resolve DIG git deps to rewritten (co-author/signed) revs

### CI
- Add flaky-test management (#489) (#9)

## [0.7.1] - 2026-07-10

### Bug Fixes
- Install the rustls crypto provider before building a reqwest client in dig.local tests (#8)

## [0.7.0] - 2026-07-10

### Features
- Ensure http://dig.local reaches the local dig-node (idempotent) (#7)

## [0.6.0] - 2026-07-07

### Features
- Pac CLI + README + per-OS acceptance scripts (#6)

## [0.5.0] - 2026-07-07

### Features
- Doctor subcommand — per-link diagnosis of both paths, --json, nonzero on no-path (#5)

## [0.4.0] - 2026-07-07

### Features
- DNS responder — UDP+TCP *.dig -> A 127.0.0.5, EDNS0/TC, wired into serve (#4)

## [0.3.0] - 2026-07-07

### Features
- HTTP gateway server — origin+proxy forms, node transport, /.dig/ control, SPA/range (#3)

## [0.2.0] - 2026-07-07

### Features
- Read path — host-form parsing (latest + pinned), content read-crypto, node contract (#2)

## [0.1.0] - 2026-07-07

### Features
- Scaffold dig-dns — SPEC, CI gate set, base32 label codec + config (#1)


