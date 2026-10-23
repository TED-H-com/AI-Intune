# P2-05 validation

Passed:

- `gofmt` and `git diff --check`.
- `go vet ./...`.
- Focused `TestDisk*`, operator route manifest, machine data disclosure,
  navigation reachability and Go formatting tests across store, web, operatoragent,
  operatorclient, Hub and agent packages.
- Full `internal/scriptcatalog` tests and repository scrubguard.
- `ops/test-disk-safe-v2.sh`: 27 tests.
- `ops/test-disk-deep-report.sh`: 11 tests.
- `ops/test-disk-clean.sh`: 14 tests.
- `ops/fleet/daily-check/test.sh`: 61 checks, including 92/93 boundary migration.
  `systemd-analyze` was unavailable, so that fixture's unit verification was skipped.
- Four server-rendered screenshot HTML fixtures, including rollback-pending. Headless Chromium failed with
  sandbox `shutdown: Operation not permitted`; PNG capture was unavailable.

Broader tests requiring TCP listeners were sandbox-blocked (`socket: operation
not permitted`). These were not product assertions failing:

- `internal/operatorclient`: `TestArtifactFetchClientCanonicalRoutesAndReplay`,
  `TestCatalogClientRoutesSchemasAndReplayEvidence`.
- `cmd/clawctl-hub`: `TestAgentTerminalLinkUnauthenticatedUpgradeRefusedBeforeAnyHandshake`,
  `TestCatalogCLIAssignmentRecoveryReplaysCommittedDarwinJob` (first arm64/lost-response case).
- `cmd/clawctl-agent`: `TestDarwinNodeJobsRunnerCompletesThroughHubHTTP`,
  `TestTerminalManagedEndpointLayoutAndCertificateEnvelope`,
  `TestDeadBATSessionEndsTerminalLink`,
  `TestTerminalDispatcherCumulativeByteBudgetTearsDownLink`,
  `TestTerminalOpenWithoutCWDStartsInTheAgentHome`,
  `TestTerminalSessionOpenFailureDoesNotEndOtherSessionOrLink`,
  `TestTerminalFrameAfterCloseIsDroppedWithoutEndingLink`,
  `TestTerminalLinkDropKillsPTYBeforeBATConnectionCloses`,
  `TestTerminalAttemptClassifiesBATDialAndProfileFailuresAsUnreachable`,
  `TestSlowBATInvokeDoesNotStopHubReader`,
  `TestTerminalHubHandshakeFailuresDoNotLeakAgentToken`,
  `TestTerminalHubRequestContract`, `TestTerminalRecordReap` (six subcases),
  `TestTerminalLinkRecordsInvocationID`, `TestTerminalLinkEndToEndRecordLifecycle`.

Implementation scope: root handoff remains blocked because this adapter has no
reviewed admin-installed root helper. Comparison measures agreement as equal
candidate-byte totals on matching UTC days against the current policy digest.
An explicit human override with reason is available. Quarantine is excluded.
No deployment, timer mutation on a live host, or commit was performed.


Daybreak corrections add tests for claimed/running/verifying rollback waits,
Hub receipt/nonce handoff under skewed and delayed observations, legacy schema
migration, ingestion rate and indexed retention, stable-key flapping and delivery
budgets, replay audits, exact UI confirmation, defaults and per-row acknowledgements.
