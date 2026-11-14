# Documentation

Every document under `docs/`, grouped by directory. The [README](../README.md) names the ones to start with.

## Guides and references

- [API / UI / CLI 能力盤點](API-SURFACE.md)
- [App Catalog and machine profiles](APP-CATALOG.md)
- [Autopilot: local admin, public HTTPS, keyed installer](AUTOPILOT.md)
- [Channels phase 3](CHANNELS.md)
- [控制面契約：API、CLI 與雙觀測](CONTROL-PLANE-CONTRACT.md)
- [Deploy clawctl-hub on Fly.io](DEPLOY-FLY.md)
- [Deploy the Hub on GCP (GCE VM)](DEPLOY-GCP.md)
- [Deploy the Hub on an Oracle Cloud VM](DEPLOY-OCI.md)
- [Open-source deploy guide — clawctl-hub (OSS / any cloud)](DEPLOY-OSS.md)
- [Devices「同步裝置資料」原語](DEVICE-SYNC.md)
- [Hub error API](ERROR_API.md)
- [Fleet error logging: implementation notes (issue filer)](ERROR_ISSUES.md)
- [Feature inventory：Intune-style workload / submenu parity](FEATURE-INVENTORY.md)
- [Fleet AI CLIs](FLEET-AI-CLIS.md)
- [Fleet health probe](FLEET-PROBE.md)
- [Host setup profile](HOST-PROFILE.md)
- [Hub observation storage and diagnostics](HUB-PERFORMANCE.md)
- [Hub reliability: database contention, notify delivery, metrics](HUB-RELIABILITY.md)
- [Hub settings](HUB-SETTINGS.md)
- [Intune 對齊覆蓋矩陣](INTUNE-COVERAGE-MATRIX.md)
- [Intune UI reference contract](INTUNE-UI-REFERENCE.md)
- [Machine Check-in Protocol & Node Management](MACHINE-CHECK-IN-PROTOCOL.md)
- [Mac agent 安裝與報到驗收](MACOS-AGENT-VALIDATION.md)
- [Disk-clean maintenance](MAINTENANCE-DISK-CLEAN.md)
- [Local maintenance timers](MAINTENANCE-TIMERS.md)
- [Monitoring: Prometheus, Alertmanager and Grafana](MONITORING.md)
- [Move agents to a new Hub](MOVE-AGENTS.md)
- [Operator MCP and CLI](OPERATOR-AGENT.md)
- [Operator identity, permissions, and browser boundary (Operator 身分、權限與瀏覽器邊界)](OPERATOR-AUTH.md)
- [Operator playbook](operator-playbook.md)
- [PRODUCT — AI-Intune / clawctl](PRODUCT.md)
- [Releases: signed Hub images on GHCR](RELEASE.md)
- [Secret providers](SECRETS.md)
- [SPEC — AI-Intune / clawctl](SPEC.md)
- [Independent verifier：producer topology 與 failure domains](VERIFIER-TOPOLOGY.md)
- [Windows agent logging](windows-agent-logging.md)
- [Windows agent 安裝與報到驗收](WINDOWS-AGENT-VALIDATION.md)

## Design notes

- [Design: Fleet error logging, Hub upload, and automatic GitHub Issues](design/fleet-error-logging.md)
- [Hub as hands: moving bot procedures onto the Hub](design/HUB-AS-HANDS.md)
- [Hub Phase 2: Standard Operations](design/HUB-PHASE2-STANDARD-OPS.md)
- [Onboarding v2: add a machine in one action](design/ONBOARDING-V2.md)
- [Hub-Controlled Stable-Release Updates](design/stable-release-updates.md)
- [Token and Model Usage Monitoring for AI Coding CLIs](design/token-usage-monitoring.md)

## Runbooks

- [BAT sweep report pilot](runbooks/BAT-SWEEP-PILOT.md)
- [Corporate network](runbooks/CORPORATE-NETWORK.md)
- [Generic deploy pattern](runbooks/DEPLOY-PATTERN.md)
- [Host migration](runbooks/HOST-MIGRATION.md)
- [New Linux host](runbooks/NEW-HOST.md)
- [Operator box SSH](runbooks/OPERATOR-BOX-SSH.md)
- [Runbooks](runbooks/README.md)
- [Restore drill (Fly Hub, Litestream → R2)](runbooks/RESTORE-DRILL.md)
- [Tool removal](runbooks/TOOL-REMOVAL.md)

## Screenshot evidence

- [Checks UI evidence](screenshots/checks/README.md)
- [Monitor-only UI evidence](screenshots/monitor-only/README.md)
- [P2-01 human UI fixtures](screenshots/phase2/p2-01/README.md)
- [P2-04 human disk actions](screenshots/phase2/p2-04/README.md)
- [P2-05 validation](screenshots/phase2/p2-05/VALIDATION.md)
