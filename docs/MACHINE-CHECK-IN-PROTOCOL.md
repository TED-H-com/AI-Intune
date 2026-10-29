# Machine Check-in Protocol & Node Management

This document defines the strict HTTP/gRPC contracts for machine check-ins, how evidence hashing is validated, deployment batching rules, and node recovery procedures.

## 1. Machine Check-in HTTP/gRPC Contracts

The communication between the endpoint agent and the Hub strictly uses these defined contracts.

- **Check-in frequency:** Agents must check-in within their defined grace period (typically 30s to 1h interval).
- **Endpoint Identity:** Check-in requires the agent's persistent identity token. A check-in will be rejected with an authentication failure if the identity token is malformed, missing, or revoked.
- **Payload:** The payload must include operating-system facts, disk space, agent version, installed features/packages state, and running process info. The state is represented as a structured JSON object over HTTP or Protocol Buffers over gRPC.
- **Time Synchronization:** The Hub determines the freshness of a check-in solely by its own clock upon receipt. The agent's local clock is not trusted for check-in freshness.
- **Settings Resolution:** In the HTTP response (or gRPC stream), the Hub provides the desired state and the resolved settings digest for that specific agent profile.

## 2. Evidence Hashing Specification

Evidence submitted by the endpoint agent or an independent verifier must follow these hashing rules:

- **Algorithm:** SHA-256 is the only supported algorithm for hashing evidence payloads, files, and state bundles.
- **Format:** The digest must be represented as a 64-character lowercase hex string.
- **Verification:** The Hub recalculates the SHA-256 hash of any incoming evidence payload before recording it. If the hash does not match, the payload is immediately rejected.
- **State Signatures:** When checking in, the agent includes the SHA-256 hash of its currently applied settings. The Hub considers a machine's settings "applied" *only* when this hash exactly matches the digest the Hub resolved for it.

## 3. Deployment Batching Rules

To ensure control plane reliability and prevent thundering herds, the Hub enforces batching rules:

- **Canary vs. Stable:** All deployments must clear a canary gate before stable promotion. A deployment starts by targeting a small percentage of nodes.
- **Concurrency Limit:** The Hub will only allow a bounded number of agents to transition states simultaneously.
- **Independent Verification Requirement:** Stable promotion requires that the effective successful canary jobs possess an active, fully reported validation from the fleet-peer agent or an independent verifier.
- **Failures Threshold:** If the failure rate of a batch exceeds the configured threshold, the rollout is paused.

## 4. Node Recovery Guide

When a node stops checking in or loses its identity, standard recovery steps are:

- **Lost Connection / Missed Window:** If an agent misses its check-in window, it enters a `stale` or `unknown` state on the Hub.
- **Credential Rotation / Revocation:** If an agent's token is revoked, it will receive an HTTP 401/403. The operator must generate a new enrollment token.
- **Re-enrollment:** Run the agent installation bootstrap again with the new `Join code` or enrollment token.
- **State Reset:** If the node's local database or persistent storage is corrupted, remove the local agent directory entirely and execute a fresh install. The Hub will re-push the canonical desired state on the first successful check-in.
