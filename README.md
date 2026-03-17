CloakCat C2 Overview

CloakCat C2 is a Rust-based Command and Control (C2) framework used for red-team style research and experimentation.

Components:
	1.	cat-server
	•	Axum-based HTTP API server.
	•	Uses sqlx with PostgreSQL for persistence (work in progress).
	•	Manages agents, commands, and execution results.
	•	Exposes operator/admin endpoints for listing agents and fetching results.
	2.	cat-agent
	•	Rust beacon/agent that:
	•	Registers itself to the server with an agent ID and platform information.
	•	Polls the server for commands.
	•	Executes shell commands on the host OS.
	•	Uploads stdout/stderr and exit codes back to the server.
	•	Signs results with an HMAC based on a per-agent token.
	3.	cat-cli
	•	Terminal-based operator CLI.
	•	Lists agents.
	•	Sends commands to specific agents.
	•	Fetches and tails results for monitoring.

Design principles:
	•	Minimal, composable, and explicit code.
	•	Clear separation between server, agent, and operator CLI.
	•	Incremental evolution:
	•	v0: In-memory server prototype (current state).
	•	v1: Database persistence for agents / commands / results.
	•	v2: Operator authentication (JWT) and role/permission model.
	•	v3: Listener profiles and multi-transport support.
	•	v4: OPSEC features (traffic camouflage, redirectors).
	•	v5: Web dashboard for C2 operations.

When adding new features:
	•	Prefer small, incremental changes.
	•	Reuse existing patterns and modules wherever possible.
	•	Keep security/OPSEC in mind but avoid premature over-engineering.

	## Architecture
3-tier Rust C2: cloakcat-protocol (shared) / cat-agent / cat-server / cat-cli

## Security Design Decisions
- Timing-safe token comparison (ring::constant_time)
- HMAC-SHA256 result integrity (shared_token, both sides verified)
- Layered auth: X-Agent-Token (registration) + X-Operator-Token (operator API)
- Optional TLS via TLS_CERT_PATH/TLS_KEY_PATH
- Release build: all debug logs stripped via #[cfg(debug_assertions)]

## Known Limitations (Intentional Scope Boundary)
- No payload encryption (AES-256-GCM planned)
- No EDR evasion (process injection not in scope)
- token_b64 DB column retained for schema compatibility (legacy)

## What I Would Add for Production
- PostgreSQL LISTEN/NOTIFY for event-driven polling
- AES-256-GCM application-layer encryption
- Domain fronting / CDN redirector support
- Agent persistence (registry/service installation)
```


**인터뷰 예상 질문과 답변 방향:**

| 질문 | 답변 포인트 |
|------|------------|
| "왜 Rust를 선택했나요?" | 메모리 안전, 정적 바이너리, 크로스컴파일 용이, EDR 탐지율 감소 |
| "Long Polling을 선택한 이유?" | 방화벽 아웃바운드 HTTP 허용 환경에서 유리, WebSocket보다 구현 단순 |
| "timing-safe 비교란?" | 일반 `==`는 첫 불일치 바이트에서 즉시 반환 → 응답시간으로 토큰 추측 가능 |
| "가장 어려웠던 점?" | HMAC 키 설계 — 에이전트와 서버 간 동일 키 보장하는 구조 설계 |
| "실무에 쓰려면 뭐가 더 필요한가요?" | EDR 우회, 페이로드 암호화, 도메인 프론팅, 에이전트 영속성 |

---

### 향후 개선 로드맵 (포트폴리오에 명시 권장)
```
단기 (1~2주):
  □ PostgreSQL LISTEN/NOTIFY로 poll 300ms busy-wait 제거
  □ stdout/stderr 크기 상한 (현재 무제한 → 1MB cap)
  □ token_b64 컬럼 migration으로 제거

중기 (1~2개월):
  □ AES-256-GCM 페이로드 암호화
  □ macOS 추가 지원 (현재 linux/windows만 build-agent 지원)
  □ 에이전트 kill_after_hours 실제 동작 구현 (DB 컬럼만 존재)

장기 (포트폴리오 v2):
  □ 도메인 프론팅 / CDN 리다이렉터
  □ 에이전트 영속성 (Windows 레지스트리, Linux systemd)
  □ 멀티 오퍼레이터 (JWT + RBAC)
  □ 웹 UI (Axum + WebSocket + React)