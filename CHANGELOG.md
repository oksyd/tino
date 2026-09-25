## [0.1.34] - 2026-09-25

### 🐛 Bug Fixes

- [**breaking**] Correct child signal handling and Landlock enforcement
- [**breaking**] Correct exec discovery and shutdown signal handling
- Pin Landlock grants and correct signal and shutdown handling
- Enforce shutdown deadlines and correct interpreter discovery
- [**breaking**] Correct CLI validation, signal handling and interpreter discovery
- Ci

### ⚙️ Miscellaneous Tasks

- *(ci)* Update
## [0.1.33] - 2026-05-17

### 🐛 Bug Fixes

- Ci

### ⚙️ Miscellaneous Tasks

- Release tino version 0.1.33
## [0.1.32] - 2026-05-16

### 🐛 Bug Fixes

- Preserve raw bytes in diagnostics

### ⚙️ Miscellaneous Tasks

- Release tino version 0.1.32
## [0.1.31] - 2026-05-16

### 🚀 Features

- [**breaking**] Harden runtime restrictions and config handling

### 🐛 Bug Fixes

- Harden runtime config validation
- Harden Landlock exec and config validation
- Harden command handling, child reaping, and config writes

### ⚙️ Miscellaneous Tasks

- Harden release and image workflows
- Release tino version 0.1.31
## [0.1.30] - 2026-05-09

### 🐛 Bug Fixes

- Harden exec allow inference and config writes
- Harden Landlock rules and release packaging

### ⚙️ Miscellaneous Tasks

- *(ci)* Update
- Release tino version 0.1.30
## [0.1.29] - 2026-05-08

### 🐛 Bug Fixes

- Harden exec allow inference and config writes

### ⚙️ Miscellaneous Tasks

- Release tino version 0.1.29
## [0.1.28] - 2026-05-08

### 🚀 Features

- Harden Landlock runtime

### 🐛 Bug Fixes

- Harden child process setup
- Reject empty command names after env expansion
- Harden Landlock rules and child supervision
- Resolve env shebang dependencies for exec restrictions
- *(unix)* Harden shebang inference and child reaping

### ⚙️ Miscellaneous Tasks

- Release tino version 0.1.28
## [0.1.27] - 2026-05-07

### 🚀 Features

- *(config)* Add line-based config generation and validation

### 🐛 Bug Fixes

- Block signal polling in supervisor loop

### ⚙️ Miscellaneous Tasks

- Release tino version 0.1.27
## [0.1.26] - 2026-04-28

### ⚙️ Miscellaneous Tasks

- *(ci)* Publish multi-arch images with native runners
- Release tino version 0.1.26
## [0.1.25] - 2026-04-27

### ⚙️ Miscellaneous Tasks

- *(ci)* Add container E2E coverage for Landlock
- *(ci)* Update
- Release tino version 0.1.25
## [0.1.24] - 2026-04-19

### ⚙️ Miscellaneous Tasks

- Release tino version 0.1.24
## [0.1.23] - 2026-04-18

### 🚜 Refactor

- Internalize runtime plumbing

### ⚙️ Miscellaneous Tasks

- Release tino version 0.1.23
## [0.1.22] - 2026-04-18

### 🐛 Bug Fixes

- Ci

### ⚙️ Miscellaneous Tasks

- Release tino version 0.1.22
## [0.1.21] - 2026-04-18

### ⚙️ Miscellaneous Tasks

- *(docs)* Update
- *(docs)* Update
- Release tino version 0.1.21
## [0.1.20] - 2026-04-18

### 🧪 Testing

- *(bench)* Add logic-path benchmarks for env and interpreter parsing

### ⚙️ Miscellaneous Tasks

- *(docs)* Update
- Release tino version 0.1.20
## [0.1.19] - 2026-04-14

### 🚀 Features

- Add Landlock TCP port restrictions
- Expand Landlock restrictions and simplify rule inputs

### ⚙️ Miscellaneous Tasks

- Release tino version 0.1.19
## [0.1.18] - 2026-03-27

### 🐛 Bug Fixes

- Ci

### ⚙️ Miscellaneous Tasks

- Release tino version 0.1.18
## [0.1.17] - 2026-03-27

### 🚀 Features

- *(cli)* Add explain mode for effective runtime configuration
- [**breaking**] Rename write restriction flags to semantic names
- Add write restriction presets

### 🐛 Bug Fixes

- *(cli)* Improve exec failure diagnostics

### ⚙️ Miscellaneous Tasks

- Release tino version 0.1.17
## [0.1.16] - 2026-03-26

### ⚙️ Miscellaneous Tasks

- Align binary release workflow and docs with release spec
- Release tino version 0.1.16
## [0.1.15] - 2026-03-26

### ⚙️ Miscellaneous Tasks

- *(ci)* Update
- Release tino version 0.1.15
## [0.1.14] - 2026-03-26

### ⚙️ Miscellaneous Tasks

- *(ci)* Update
- Release tino version 0.1.14
## [0.1.13] - 2026-03-20

### ⚙️ Miscellaneous Tasks

- *(ci)* Update
- Release tino version 0.1.13
## [0.1.12] - 2026-03-20

### ⚙️ Miscellaneous Tasks

- *(ci)* Update
- Release tino version 0.1.12
## [0.1.11] - 2026-03-20

### 🚀 Features

- Add explicit child command environment expansion via --expand-env

### ⚙️ Miscellaneous Tasks

- Add .justfile
- Release tino version 0.1.11
## [0.1.10] - 2026-01-15

### 🚀 Features

- *(runtime)* Harden PID1 signal handling and CLI UX
- *(landlock)* Add write allowlist sandbox and Docker seccomp profile

### ⚙️ Miscellaneous Tasks

- Update Cargo.toml
- *(ci)* Update release.yaml
- *(docs)* Update
- *(docs)* Update
- *(docs)* Update
- Release tino version 0.1.10
## [0.1.9] - 2025-12-15

### 🐛 Bug Fixes

- *(ci)* Remove nix::Error::as_errno and satisfy -D warnings
- Address collapsible-if in signal forwarding
- Ci
- *(ci)* Avoid test hangs and restore empty-CMD behavior
- Ci

### ⚙️ Miscellaneous Tasks

- Release tino version 0.1.9
## [0.1.8] - 2025-12-15

### 🚀 Features

- *(runtime)* Harden unix PID1 flow and add coverage

### 🐛 Bug Fixes

- *(pid1)* Avoid hanging after main child exits

### ⚙️ Miscellaneous Tasks

- Update Dockerfile
- Release tino version 0.1.8
## [0.1.7] - 2025-09-20

### 🚜 Refactor

- Split CLI and platform modules

### ⚙️ Miscellaneous Tasks

- *(docs)* Update README.md
- Release tino version 0.1.7
## [0.1.6] - 2025-06-30

### ⚙️ Miscellaneous Tasks

- (ci) update release.yaml
- Release tino version 0.1.6
## [0.1.5] - 2025-06-30

### 🐛 Bug Fixes

- Typo

### ⚙️ Miscellaneous Tasks

- Release tino version 0.1.5
## [0.1.4] - 2025-06-30

### ⚙️ Miscellaneous Tasks

- (ci) update release.yaml
- Release tino version 0.1.4
## [0.1.3] - 2025-06-30

### ⚙️ Miscellaneous Tasks

- Update Cargo.toml
- Add LICENSE
- Release tino version 0.1.3
## [0.1.2] - 2025-06-30

### ⚙️ Miscellaneous Tasks

- Add CHANGELOG.md
- Release tino version 0.1.2
## [0.1.1] - 2025-06-30

### ⚙️ Miscellaneous Tasks

- Init commit
- Update Cargo.toml
- Release tino version 0.1.1
